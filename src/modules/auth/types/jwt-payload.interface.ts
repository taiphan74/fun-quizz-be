import { UserRole } from '../../users/user-role.enum';

export interface JwtPayload {
  sub: string;
  username: string;
  email: string;
  role: UserRole;
}
