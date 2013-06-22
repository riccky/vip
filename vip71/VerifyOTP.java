/*
 * VIP サービスの OTP 検証サービス API
 * 参考 URL
 * http://www.symantec.com/verisign/vip-authentication-service/renewals-upgrades-licensing
 */

package vip71;

import java.math.BigInteger;
import java.util.Properties;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;

import com.verisign.www._2006._08.vipservice.ActivateTokenResponseType;
import com.verisign.www._2006._08.vipservice.ActivateTokenType;
import com.verisign.www._2006._08.vipservice.GetServerTimeResponseType;
import com.verisign.www._2006._08.vipservice.GetServerTimeType;
import com.verisign.www._2006._08.vipservice.SynchronizeResponseType;
import com.verisign.www._2006._08.vipservice.SynchronizeType;
import com.verisign.www._2006._08.vipservice.ValidateResponseType;
import com.verisign.www._2006._08.vipservice.ValidateType;
import com.verisign.www._2006._08.vipservice.ValidateMultipleResponseType;
import com.verisign.www._2006._08.vipservice.ValidateMultipleType;
import com.verisign.www._2006._08.vipservice.VipSoapInterface;
import com.verisign.www._2006._08.vipservice.VipSoapInterfaceService;
import com.verisign.www._2006._08.vipservice.VipSoapInterfaceServiceLocator;
import com.verisign.www._2006._08.vipservice.TokenIdType;

/**
 * OTP 値検証系 API
 *  Activate
 *  Validate
 *  Validate Multiple
 *  Synchronize
 *
 * @author r-takada
 *
 */
public class VerifyOTP {
	VipSoapInterfaceService service;
	VipSoapInterface port;
	String m_url;
	String version = "2.0";
	String nonce = "abcd1234";

	public VerifyOTP() {
		try {
			service = new VipSoapInterfaceServiceLocator();
			Properties config = new Properties();
			config.load(new FileInputStream("vip.properties"));
			String url = config.getProperty("vipurl");
			String certFile = config.getProperty("javax.net.ssl.keyStore");
			String password = config.getProperty("javax.net.ssl.keyStorePassword");
			String proxyHost = config.getProperty("https.proxyHost");
			String proxyPort = config.getProperty("https.proxyPort");

			m_url = url;
			System.setProperty("javax.net.ssl.keyStoreType", "pkcs12");
			System.setProperty("javax.net.ssl.keyStore", certFile);
			System.setProperty("javax.net.ssl.keyStorePassword", password);
			if ( proxyHost != null || proxyPort != null){
				System.setProperty("https.proxyHost", proxyHost);
				System.setProperty("https.proxyPort", proxyPort);
			}
		}
		catch (Exception e)
		{
			System.out.println("Exception : " + e);
		}
	}

	public String getServerTime(){
		try {
			port = service.getvipServiceAPI (new java.net.URL(m_url+"/prov/soap"));
			GetServerTimeType x = new GetServerTimeType(version, nonce);
			GetServerTimeResponseType resp = port.getServerTime(x);
			BigInteger reason = new BigInteger(resp.getStatus().getReasonCode());
			if (reason.intValue() != 0) {
				System.out.println("ReasonCode =" + reason.toString(16));
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("ErrorDetail =" + resp.getStatus().getErrorDetail());
				return null;
			} else {
				return (resp.getTimestamp().getTime().toString());
			}
		}
		catch (Exception e) {
			System.out.println("getServerTime(), Exception : " + e);
			return null;
		}
	}

	/**
	 * Activate API
	 * 初回登録用 API の検証
	 *
	 */
	public void ActivationToken () {
		try {
			port = service.getvipServiceAPI(new java.net.URL(m_url + "/mgmt/soap"));
			BufferedReader ibuf = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("TokenID:");
			TokenIdType TokenId = new TokenIdType(ibuf.readLine());
			System.out.println("OTP1:");
			String OTP1 = ibuf.readLine();
			System.out.println("OTP2:");
			String OTP2 = ibuf.readLine();
			ActivateTokenType x = new ActivateTokenType(version,nonce,TokenId,OTP1,OTP2);
			ActivateTokenResponseType resp = port.activateToken(x);
			BigInteger reason = new BigInteger(resp.getStatus().getReasonCode());
			if (reason.intValue() != 0) {
				System.out.println("ReasonCode =" + reason.toString(16));
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("ErrorDetail =" + resp.getStatus().getErrorDetail());
			} else {
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("SameInitialState =" + resp.getSameInitialState());
			}
		} catch (Exception e) {
			System.out.println("ActivateToken(), Exception : " + e);
		}
	}

	/**
	 * Validate API
	 * OTP 値の検証
	 *
	 */
	public void ValidateOTP () {
		try {
			port = service.getvipServiceAPI(new java.net.URL(m_url + "/val/soap"));
			BufferedReader ibuf = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("TokenID:");
			TokenIdType TokenId = new TokenIdType(ibuf.readLine());
			System.out.println("OTP:");
			String OTP = ibuf.readLine();
			ValidateType x = new ValidateType(version,nonce,TokenId,OTP);
			ValidateResponseType resp = port.validate(x);
			BigInteger reason = new BigInteger(resp.getStatus().getReasonCode());
			if (reason.intValue() != 0) {
				System.out.println("ReasonCode =" + reason.toString(16));
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("ErrorDetail =" + resp.getStatus().getErrorDetail());
			} else {
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
			}
		} catch (Exception e) {
			System.out.println("ValidateOTP(), Exception : " + e);
		}
	}

	/**
	 * Synchronize API
	 * OTP 同期用 API の検証
	 *
	 */
	public void SynchronizeOTP () {
		try {
			port = service.getvipServiceAPI(new java.net.URL(m_url + "/val/soap"));
			BufferedReader ibuf = new BufferedReader(new InputStreamReader(System.in));
			System.out.println("TokenID:");
			TokenIdType TokenId = new TokenIdType(ibuf.readLine());
			System.out.println("OTP1:");
			String OTP1 = ibuf.readLine();
			System.out.println("OTP2:");
			String OTP2 = ibuf.readLine();
			SynchronizeType x = new SynchronizeType(version,nonce,TokenId,OTP1,OTP2);
			SynchronizeResponseType resp = port.synchronize(x);
			BigInteger reason = new BigInteger(resp.getStatus().getReasonCode());
			if (reason.intValue() != 0) {
				System.out.println("ReasonCode =" + reason.toString(16));
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("ErrorDetail =" + resp.getStatus().getErrorDetail());
			} else {
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
			}
		} catch (Exception e) {
			System.out.println("SynchronizeOTP(), Exception : " + e);
		}
	}

	/**
	 * ValidateMultiple API
	 * 複数トークン ID による OTP 検証
	 * 複数トークン ID を所有しているユーザ用 API
	 *
	 */
	public void ValidateMultipleOTP () {
		try {
			port = service.getvipServiceAPI(new java.net.URL(m_url + "/val/soap"));
			BufferedReader ibuf = new BufferedReader(new InputStreamReader(System.in));
			TokenIdType[] TokenIds = new TokenIdType[3];
			for ( int i = 0; i < 3; i++ ){
				System.out.println("TokenID" + i + ":");
				TokenIdType tid = new TokenIdType(ibuf.readLine());
				TokenIds[i] = tid;
			}
			System.out.println("OTP:");
			String OTP = ibuf.readLine();
			ValidateMultipleType x = new ValidateMultipleType(version,nonce,TokenIds,OTP);
			ValidateMultipleResponseType resp = port.validateMultiple(x);
			BigInteger reason = new BigInteger(resp.getStatus().getReasonCode());
			if (reason.intValue() != 0) {
				System.out.println("ReasonCode =" + reason.toString(16));
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
				System.out.println("ErrorDetail =" + resp.getStatus().getErrorDetail());
			} else {
				System.out.println("StatusMessage =" + resp.getStatus().getStatusMessage());
			}
		} catch (Exception e) {
			System.out.println("ValidateMultipleOTP(), Exception : " + e);
		}
	}

	public static void main(String[] args) throws Exception {
		BufferedReader mbuf = new BufferedReader(new InputStreamReader(System.in));
		VerifyOTP c = new VerifyOTP();
		System.out.println("Select Type:[1]Activation [2]Validate [3]Synchronize [4]ValidateMultiple");
		String Type = mbuf.readLine();

		if (Type.equals("1")) {
			System.out.println("Server Time =" + c.getServerTime());
			c.ActivationToken();
		}
		else if (Type.equals("2")) {
			System.out.println("Server Time =" + c.getServerTime());
			c.ValidateOTP();
		}
		else if (Type.equals("3")) {
			System.out.println("Server Time =" + c.getServerTime());
			c.SynchronizeOTP();
		}

		else if (Type.equals("4")) {
			System.out.println("Server Time =" + c.getServerTime());
			c.ValidateMultipleOTP();
		}

		else {
			System.out.println("Select correct number");
		}
	}
}
