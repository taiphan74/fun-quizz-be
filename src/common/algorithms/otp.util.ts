import { randomInt } from 'crypto';

export const generateNumericOtp = (length = 6): string => {
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error('OTP length must be a positive integer');
  }

  const min = 10 ** (length - 1);
  const max = 10 ** length - 1;
  return randomInt(min, max + 1).toString();
};
