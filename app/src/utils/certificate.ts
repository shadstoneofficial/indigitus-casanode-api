import * as path from 'path';
import fs from 'fs-extra';
import forge from 'node-forge';
import * as crypto from 'crypto';
import { getLocalIPAddress } from '@utils/network';
import config from './configuration';
import { Logger } from './logger';

export interface CertificateInfo
{
	creationDate: string;
	expirationDate: string;
	issuer: string;
	subject: string;
}

class CertificateManager
{
	private static instance: CertificateManager;
	
	// Default paths for certificate and key files
	private certFilePath: string = path.join(config.CONFIG_DIR, 'tls.crt');
	private keyFilePath: string = path.join(config.CONFIG_DIR, 'tls.key');
	private nodeCountry: string = 'NA';
	
	private constructor() {}
	
	/**
	 * Get instance of CertificateManager
	 * @returns CertificateManager
	 */
	public static getInstance(): CertificateManager
	{
		if (!CertificateManager.instance)
		{
			CertificateManager.instance = new CertificateManager();
		}
		return CertificateManager.instance;
	}
	
	/**
	 * Generate a new certificate and key pair
	 * @param validityYears - Number of years the certificate is valid for
	 * @param certPath - Path for the certificate file
	 * @param keyPath - Path for the key file
	 * @returns boolean - True if the certificate was successfully generated, false otherwise
	 */
	public async generate(
		validityYears: number = 1,
		certPath?: string,
		keyPath?: string
	): Promise<boolean>
	{
		try
		{
			// Use custom paths if provided, otherwise default paths
			const certFilePath = certPath || this.certFilePath;
			const keyFilePath = keyPath || this.keyFilePath;

			// Get local IP address
			const localIPAddress = getLocalIPAddress();

			// Ensure the directory for the certificate and key files exists
			await fs.ensureDir(path.dirname(certFilePath));
			await fs.ensureDir(path.dirname(keyFilePath));

			// If the certificate file exists, remove it
			if (await fs.pathExists(certFilePath))
				await fs.remove(certFilePath);
			
			// If the key file exists, remove it
			let cert = forge.pki.createCertificate();
			let publicKey: forge.pki.rsa.PublicKey;
			let privateKey: forge.pki.rsa.PrivateKey;
			
			// Generate a new RSA key pair for the server certificate
			const keys = forge.pki.rsa.generateKeyPair(2048);
			publicKey = keys.publicKey;
			privateKey = keys.privateKey;
			
			// Set certificate validity
			cert.serialNumber = (Math.floor(Math.random() * 100000)).toString();
			cert.validity.notBefore = new Date();
			cert.validity.notAfter = new Date();
			cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + validityYears);
			
			// Define certificate attributes
			const attrs: forge.pki.CertificateField[] = [
				{ name: 'countryName', value: this.nodeCountry, shortName: 'C' },
				{ name: 'organizationName', value: 'NA', shortName: 'O' },
				{ name: 'stateOrProvinceName', value: 'NA', shortName: 'ST' },
				{ name: 'commonName', value: localIPAddress || '', shortName: 'CN' }
			];
			
			// Set subject for the server certificate
			cert.setSubject(attrs);
			cert.publicKey = publicKey;
			
			// Generate a per-node self-signed certificate. Shared CA material is
			// deliberately unsupported and must never be packaged with the API.
			cert.setIssuer(attrs);
			cert.setExtensions([
				{ name: 'basicConstraints', cA: false },
				{ name: 'keyUsage', digitalSignature: true, keyEncipherment: true, dataEncipherment: true, },
				{ name: 'extKeyUsage', serverAuth: true, clientAuth: true, },
				{ name: 'subjectAltName', altNames: [{ type: 7, ip: localIPAddress }] }
			]);
			cert.sign(privateKey, forge.md.sha256.create());

			const pemCert = forge.pki.certificateToPem(cert);
			await fs.writeFile(certFilePath, pemCert);

			const privateKeyPem = forge.pki.privateKeyToPem(privateKey);
			await fs.writeFile(keyFilePath, privateKeyPem);

			Logger.info('Self-signed certificate and key have been generated.');
			return true;
		}
		catch (error)
		{
			if (error instanceof Error)
				Logger.error(`Failed to generate certificate: ${error.message}`);
			else
				Logger.error(`Failed to generate certificate: ${String(error)}`);
		}
		
		return false;
	}
	
	/**
	 * Get certificate information
	 * @param certPath - Optional path for the certificate file
	 * @returns CertificateInfo | null
	 */
	public info(certPath?: string): CertificateInfo | null
	{
		try
		{
			const certFilePath = certPath || this.certFilePath;
			
			// Check if the certificate file do not exists
			if (!fs.pathExistsSync(certFilePath))
			{
				Logger.info('Certificate or key file not found.');
				return null;
			}
			
			// Read the certificate file
			const pemCert = fs.readFileSync(certFilePath, 'utf-8');
			
			// Parse certificate using Node.js crypto module (supports both RSA and ECDSA)
			const cert = new crypto.X509Certificate(pemCert);
			
			// Return certificate information
			return {
				creationDate: new Date(cert.validFrom).toISOString(),
				expirationDate: new Date(cert.validTo).toISOString(),
				issuer: cert.issuer,
				subject: cert.subject,
			} as CertificateInfo;
		}
		catch (error)
		{
			if (error instanceof Error)
				Logger.error(`Failed to read certificate: ${error.message}`);
			else
				Logger.error(`Failed to read certificate: ${String(error)}`);
		}
		
		return null;
	}
	
	/**
	 * Remove certificate and key files
	 * @param certPath - Optional path for the certificate file
	 * @param keyPath - Optional path for the key file
	 * @returns boolean - True if files were successfully removed, false otherwise
	 */
	public async remove(certPath?: string, keyPath?: string): Promise<boolean>
	{
		try
		{
			const certFilePath = certPath || this.certFilePath;
			const keyFilePath = keyPath || this.keyFilePath;
			
			// If certificate files do not exist, return true
			if (!await fs.pathExists(certFilePath) && !await fs.pathExists(keyFilePath))
				return true;
			
			// Remove the certificate and key files
			await fs.remove(certFilePath);
			await fs.remove(keyFilePath);
			
			Logger.info('Certificate files have been removed.');
			return true;
		}
		catch (error)
		{
			if (error instanceof Error)
				Logger.error(`Failed to remove certificate files: ${error.message}`);
			else
				Logger.error(`Failed to remove certificate files: ${String(error)}`);
		}
		
		return false;
	}
}

// Create a singleton instance of certificateManager
const certificateManager = CertificateManager.getInstance();
export default certificateManager;

export const certificateGenerate = (validityYears = 1, certPath?: string, keyPath?: string): Promise<boolean> => certificateManager.generate(validityYears, certPath, keyPath);
export const certificateInfo = (certPath?: string): CertificateInfo | null => certificateManager.info(certPath);
export const certificateRemove = (certPath?: string, keyPath?: string): Promise<boolean> => certificateManager.remove(certPath, keyPath);
