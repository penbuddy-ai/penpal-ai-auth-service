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
  // Subscription fields
  subscriptionPlan?: "monthly" | "yearly" | null;
  subscriptionStatus?:
    | "trial"
    | "active"
    | "past_due"
    | "canceled"
    | "unpaid"
    | null;
  subscriptionTrialEnd?: Date;
  hasActiveSubscription?: boolean;
  cancelAtPeriodEnd?: boolean;
};
