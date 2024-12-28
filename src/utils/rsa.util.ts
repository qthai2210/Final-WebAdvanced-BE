import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class RsaUtil {
  constructor(private configService: ConfigService) {}

  encryptWithPublicKey(data: any): string {
    // Generate a random AES key
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    // Encrypt the data with AES
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    const jsonData = JSON.stringify(data);
    let encryptedData = cipher.update(jsonData, 'utf8', 'base64');
    encryptedData += cipher.final('base64');

    // Encrypt the AES key with RSA
    const publicKey = this.configService.get('EXTERNAL_BANK_PUBLIC_KEY');
    const encryptedKey = crypto.publicEncrypt(
      {
        key: publicKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      },
      Buffer.concat([aesKey, iv]),
    );

    // Return both encrypted key and data
    return JSON.stringify({
      key: encryptedKey.toString('base64'),
      data: encryptedData,
    });
  }

  decryptWithPrivateKey(encryptedPackage: string): any {
    try {
      const { key: encryptedKey, data: encryptedData } =
        JSON.parse(encryptedPackage);

      // Decrypt the AES key with RSA
      const privateKey = this.configService.get('BANK_PRIVATE_KEY');
      const keyAndIv = crypto.privateDecrypt(
        {
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(encryptedKey, 'base64'),
      );

      // Extract AES key and IV
      const aesKey = keyAndIv.slice(0, 32);
      const iv = keyAndIv.slice(32);

      // Decrypt the data with AES
      const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
      let decryptedData = decipher.update(encryptedData, 'base64', 'utf8');
      decryptedData += decipher.final('utf8');

      return JSON.parse(decryptedData);
    } catch (error) {
      console.error('Decryption error:', error);
      throw new Error('Failed to decrypt data: ' + error.message);
    }
  }

  // Optional: Add method to validate encrypted package format
  private validateEncryptedPackage(encryptedPackage: string): boolean {
    try {
      const parsed = JSON.parse(encryptedPackage);
      return typeof parsed.key === 'string' && typeof parsed.data === 'string';
    } catch {
      return false;
    }
  }
}
