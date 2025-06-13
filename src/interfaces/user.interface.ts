export type User = {
  _id: string;
  firstName: string;
  lastName: string;
  email: string;
  password?: string;
  isEmailVerified: boolean;
  verificationToken?: string;
  resetPasswordToken?: string;
  resetPasswordExpires?: Date;
  provider: string;
  googleId?: string;
  role: string;
  refreshToken?: string;
};
