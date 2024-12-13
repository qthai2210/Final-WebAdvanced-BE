import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { Transaction } from '../models/transactions/schemas/transaction.schema';
import {
  TransactionHistoryQueryDto,
  TransactionHistoryResponseDto,
} from './dto/transaction-history.dto';

@Injectable()
export class TransactionService {
  constructor(
    @InjectModel(Transaction.name) private transactionModel: Model<Transaction>,
  ) {}

  async getTransactionHistory(
    query: TransactionHistoryQueryDto,
  ): Promise<TransactionHistoryResponseDto[]> {
    const {
      accountNumber,
      type = 'all',
      page = 1,
      limit = 10,
      fromDate,
      toDate,
    } = query;

    // Convert page và limit sang number
    const pageNum = parseInt(page.toString(), 10);
    const limitNum = parseInt(limit.toString(), 10);

    const matchQuery: any = {
      status: 'completed',
      $or: [{ fromAccount: accountNumber }, { toAccount: accountNumber }],
    };

    if (type !== 'all') {
      switch (type) {
        case 'received':
          matchQuery.toAccount = accountNumber;
          break;
        case 'sent':
          matchQuery.fromAccount = accountNumber;
          matchQuery.type = 'internal_transfer';
          break;
        case 'debt_payment':
          matchQuery.type = 'debt_payment';
          break;
      }
    }

    if (fromDate && toDate) {
      matchQuery.createdAt = {
        $gte: new Date(fromDate),
        $lte: new Date(toDate),
      };
    }

    return this.transactionModel
      .aggregate([
        { $match: matchQuery },
        { $sort: { createdAt: -1 } },
        { $skip: (pageNum - 1) * limitNum }, // Sử dụng giá trị đã convert
        { $limit: limitNum }, // Sử dụng giá trị đã convert
        {
          $lookup: {
            from: 'banks',
            localField: 'bankId',
            foreignField: '_id',
            as: 'bank',
          },
        },
        {
          $project: {
            id: '$_id',
            type: 1,
            amount: 1,
            fromAccount: 1,
            toAccount: 1,
            content: 1,
            fee: 1,
            status: 1,
            createdAt: 1,
            bankId: 1,
            'bank.name': 1,
            direction: {
              $cond: {
                if: { $eq: ['$toAccount', accountNumber] },
                then: 'in',
                else: 'out',
              },
            },
          },
        },
      ])
      .exec();
  }
}
