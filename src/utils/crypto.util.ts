import { Injectable } from '@nestjs/common';
import * as crypto from 'crypto';

@Injectable()
export class CryptoUtil {
  generateHash(data: any, secretKey: string): string {
    return crypto
      .createHmac('SHA256', secretKey)
      .update(typeof data === 'string' ? data : JSON.stringify(data))
      .digest('hex');
  }

  generateAPIHash(payload: any, timestamp: string, secretKey: string): string {
    try {
      // Ensure stable stringification
      const sortedPayload = this.sortObjectKeys(payload);
      const dataString = JSON.stringify(sortedPayload);
      const hashInput = `${dataString}${timestamp}`;

      console.log('Hash generation:', {
        dataString,
        timestamp,
        secretKey,
        hashInput,
      });

      return crypto
        .createHmac('SHA256', secretKey)
        .update(hashInput)
        .digest('hex');
    } catch (error) {
      console.error('Hash generation error:', error);
      throw error;
    }
  }

  private sortObjectKeys(obj: any): any {
    if (obj === null || typeof obj !== 'object') {
      return obj;
    }

    if (Array.isArray(obj)) {
      return obj.map((item) => this.sortObjectKeys(item));
    }

    return Object.keys(obj)
      .sort()
      .reduce((result, key) => {
        result[key] = this.sortObjectKeys(obj[key]);
        return result;
      }, {});
  }

  private normalizeKeyString(keyString: string): string {
    return keyString.split(String.raw`\n`).join('\n');
  }

  private decodeBase64Key(base64Key: string): string {
    try {
      const normalizedKey = this.normalizeKeyString(base64Key);
      return Buffer.from(normalizedKey, 'base64').toString('utf-8');
    } catch (error) {
      console.error('Base64 decoding error:', error);
      throw new Error('Invalid key format');
    }
  }

  private cleanupKey(key: string): string {
    return key
      .replace(/\\n/g, '\n') // Replace literal \n with newlines
      .replace(/["']/g, '') // Remove quotes
      .trim();
  }

  private formatKey(key: string, isPrivate = false): string {
    try {
      // Remove all whitespace and normalize newlines
      const cleanKey = key
        .replace(/\\n/g, '\n')
        .replace(/[\r\s]/g, '')
        .trim();

      // If key already has headers, clean up the format
      if (cleanKey.includes('-----BEGIN')) {
        const keyContent = cleanKey
          .replace(/-----BEGIN[\s\S]+?-----/, '')
          .replace(/-----END[\s\S]+?-----/, '')
          .trim();

        // Format with 64-character lines
        const chunks = keyContent.match(/.{1,64}/g) || [];
        const formattedKey = chunks.join('\n');

        if (isPrivate) {
          return `-----BEGIN RSA PRIVATE KEY-----\n${formattedKey}\n-----END RSA PRIVATE KEY-----`;
        }
        return `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n-----END PUBLIC KEY-----`;
      }

      // Handle raw key content
      const chunks = cleanKey.match(/.{1,64}/g) || [];
      const formattedKey = chunks.join('\n');

      if (isPrivate) {
        return `-----BEGIN RSA PRIVATE KEY-----\n${formattedKey}\n-----END RSA PRIVATE KEY-----`;
      }
      return `-----BEGIN PUBLIC KEY-----\n${formattedKey}\n${formattedKey}\n-----END PUBLIC KEY-----`;
    } catch (error) {
      console.error('Key formatting error:', error);
      throw new Error(`Failed to format key: ${error.message}`);
    }
  }

  signData(data: any, privateKey: string): string {
    try {
      const sign = crypto.createSign('SHA256');
      const dataString = typeof data === 'string' ? data : JSON.stringify(data);
      sign.update(dataString);

      const formattedKey = this.formatKey(privateKey, true);
      console.log('Private key after cleanup:', formattedKey);

      // Use simple sign method with the key directly
      return sign.sign(formattedKey, 'base64');
    } catch (error) {
      console.error('Signing error:', {
        error: error.message,
        formattedKey: privateKey.substring(0, 100) + '...',
      });
      throw new Error(`Failed to sign data: ${error.message}`);
    }
  }

  verifySignature(data: any, signature: string, publicKey: string): boolean {
    try {
      const verify = crypto.createVerify('SHA256');
      const dataString = typeof data === 'string' ? data : JSON.stringify(data);
      verify.update(dataString);

      const formattedKey = this.formatKey(publicKey, false);

      return verify.verify(formattedKey, Buffer.from(signature, 'base64'));
    } catch (error) {
      console.error('Verification error:', error);
      throw new Error(`Failed to verify signature: ${error.message}`);
    }
  }

  encodeTransactionData(
    transaction: any,
    privateKey: string,
    secretKey: string,
  ): string {
    // Sort keys to ensure consistent JSON stringification
    const sortedTransaction = Object.keys(transaction)
      .sort()
      .reduce((obj, key) => {
        obj[key] = transaction[key];
        return obj;
      }, {});

    const signature = this.signData(sortedTransaction, privateKey);
    const timestamp = new Date().toISOString();
    const hash = this.generateAPIHash(sortedTransaction, timestamp, secretKey);

    return JSON.stringify({
      data: sortedTransaction,
      signature,
      timestamp,
      hash,
    });
  }

  decodeTransactionData(
    transferData: string,
    //publicKey: string,
    //secretKey: string,
  ): any {
    try {
      // Parse transferData string to object
      const data = JSON.parse(transferData);

      // Verify signature and hash are not needed here since transferData
      // is already a plain JSON string

      return data;
    } catch (error) {
      console.error('Decoding error:', error);
      throw new Error('Invalid transfer data format');
    }
  }
}
