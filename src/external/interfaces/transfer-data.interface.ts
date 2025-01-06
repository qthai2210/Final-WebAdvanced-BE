export interface TransferData {
  fromAccount: string;
  toAccount: string;
  amount: number;
  content: string;
  sourceBankId: string;
  timestamp: string;
  fee: number;
  feeType: string;
}
