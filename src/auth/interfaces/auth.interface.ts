export interface AuthData {
  access_token: string;
  user: {
    id: string;
    username: string;
    email: string;
    role: string;
    status: string;
    fullName: string;
  };
}
