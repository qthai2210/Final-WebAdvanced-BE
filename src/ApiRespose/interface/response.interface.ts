export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: number;
    message: string;
  };
  timestamp: string;
}

export const createSuccessResponse = <T>(data: T): ApiResponse<T> => ({
  success: true,
  data,
  timestamp: new Date().toISOString(),
});

export const createErrorResponse = (
  code: number,
  message: string,
): ApiResponse<null> => ({
  success: false,
  error: {
    code,
    message,
  },
  timestamp: new Date().toISOString(),
});
