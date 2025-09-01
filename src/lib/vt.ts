import axios, { AxiosInstance } from 'axios';
import { IOCType } from './validators';

interface VTResponse {
  data: {
    attributes: {
      last_analysis_stats?: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout?: number;
      };
      reputation?: number;
      categories?: Record<string, string>;
      tags?: string[];
      last_modification_date?: number;
      creation_date?: number;
    };
    id: string;
    type: string;
  };
}

class VirusTotalClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: 'https://www.virustotal.com/api/v3',
      headers: {
        'x-apikey': process.env.VT_API_KEY || '',
        'Content-Type': 'application/json',
      },
      timeout: 30000,
    });
  }

  async lookupIOC(ioc: string, type: IOCType): Promise<VTResponse> {
    try {
      let endpoint = '';
      
      switch (type) {
        case 'ip':
          endpoint = `/ip_addresses/${ioc}`;
          break;
        case 'domain':
          endpoint = `/domains/${ioc}`;
          break;
        case 'hash':
          endpoint = `/files/${ioc}`;
          break;
        case 'url':
          const urlId = Buffer.from(ioc).toString('base64').replace(/=/g, '');
          endpoint = `/urls/${urlId}`;
          break;
        default:
          throw new Error(`Unsupported IOC type: ${type}`);
      }

      const response = await this.client.get<VTResponse>(endpoint);
      return response.data;
      
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.status === 404) {
        return {
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 0,
                undetected: 0,
                harmless: 0,
              },
            },
            id: ioc,
            type,
          },
        };
      }
      throw error;
    }
  }
}

export const vtClient = new VirusTotalClient();
