import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';
import type { Profile } from 'passport-google-oauth20';
import { AuthProviderType, type User } from '@prisma/client';
import { PrismaService } from '../../../common/prisma/prisma.service';
import { UserRole } from '../../users/user-role.enum';

interface GoogleAccountPayload {
  email?: string | null;
  givenName?: string | null;
  familyName?: string | null;
  providerAccountId?: string | null;
}

@Injectable()
export class GoogleAuthService {
  constructor(private readonly prisma: PrismaService) {}

  async loginWithGoogleProfile(profile: Profile): Promise<User> {
    return this.findOrCreateGoogleUser({
      email: profile.emails?.[0]?.value,
      givenName: profile.name?.givenName,
      familyName: profile.name?.familyName,
      providerAccountId: profile.id,
    });
  }

  private async findOrCreateGoogleUser(
    payload: GoogleAccountPayload,
  ): Promise<User> {
    const email = payload.email;
    const providerAccountId = payload.providerAccountId;

    if (!email) {
      throw new UnauthorizedException('Google account is missing an email');
    }

    if (providerAccountId) {
      const provider = await this.prisma.authProvider.findFirst({
        where: {
          provider: AuthProviderType.GOOGLE,
          providerAccountId,
        },
        include: { user: true },
      });
      if (provider?.user) {
        if (!provider.user.emailVerified) {
          await this.prisma.user.update({
            where: { id: provider.user.id },
            data: { emailVerified: true },
          });
        }
        return provider.user;
      }
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      const updateEmailVerified = !existingUser.emailVerified;
      await this.ensureAuthProviderExists(
        existingUser.id,
        AuthProviderType.GOOGLE,
        providerAccountId,
      );
      if (updateEmailVerified) {
        await this.prisma.user.update({
          where: { id: existingUser.id },
          data: { emailVerified: true },
        });
      }
      return existingUser;
    }

    const username = await this.generateUniqueUsername(email);
    const hashPassword = await bcrypt.hash(this.generateRandomPassword(), 10);

    return this.prisma.$transaction(async (tx) => {
      const createdUser = await tx.user.create({
        data: {
          email,
          username,
          firstName: payload.givenName ?? '',
          lastName: payload.familyName ?? '',
          role: UserRole.USER,
          hashPassword,
          emailVerified: true,
        },
      });

      await tx.authProvider.create({
        data: {
          userId: createdUser.id,
          provider: AuthProviderType.GOOGLE,
          providerAccountId,
        },
      });

      return createdUser;
    });
  }

  private async ensureAuthProviderExists(
    userId: string,
    provider: AuthProviderType,
    providerAccountId?: string | null,
  ): Promise<void> {
    const existingProvider = await this.prisma.authProvider.findFirst({
      where: { userId, provider },
    });

    if (existingProvider) {
      if (providerAccountId && !existingProvider.providerAccountId) {
        await this.prisma.authProvider.update({
          where: { id: existingProvider.id },
          data: { providerAccountId },
        });
      }
      return;
    }

    await this.prisma.authProvider.create({
      data: {
        userId,
        provider,
        providerAccountId: providerAccountId ?? undefined,
      },
    });
  }

  private async generateUniqueUsername(email: string): Promise<string> {
    const prefix = email.split('@')[0]?.replace(/[^a-zA-Z0-9]/g, '') || 'user';
    const base = prefix.length > 0 ? prefix.toLowerCase() : 'user';
    let candidate = base;
    let attempt = 0;

    while (
      await this.prisma.user.findUnique({
        where: { username: candidate },
      })
    ) {
      attempt += 1;
      candidate = `${base}${attempt}`;
    }

    return candidate;
  }

  private generateRandomPassword(): string {
    return randomBytes(24).toString('hex');
  }
}
