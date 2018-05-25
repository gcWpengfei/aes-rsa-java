package com.wustrive;

import java.util.TreeMap;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.wustrive.aesrsa.util.AES;
import com.wustrive.aesrsa.util.EncryUtil;
import com.wustrive.aesrsa.util.RSA;
import com.wustrive.aesrsa.util.RandomUtil;

/**
 * AES+RSA签名，加密 验签，解密
* @ClassName: Main 
* @Description: TODO(这里用一句话描述这个类的作用) 
* @author wustrive
* @date 2015年8月23日 上午1:14:27 
*
 */
public class Main 
{
	/*public static final String  clientPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKbNojYr8KlqKD/y"+
												"COd7QXu3e4TsrHd4sz3XgDYWEZZgYqIjVDcpcnlztwomgjMj9xSxdpyCc85GOGa0"+
												"lva1fNZpG6KXYS1xuFa9G7FRbaACoCL31TRv8t4TNkfQhQ7e2S7ZktqyUePWYLlz"+
												"u8hx5jXdriErRIx1jWK1q1NeEd3NAgMBAAECgYAws7Ob+4JeBLfRy9pbs/ovpCf1"+
												"bKEClQRIlyZBJHpoHKZPzt7k6D4bRfT4irvTMLoQmawXEGO9o3UOT8YQLHdRLitW"+
												"1CYKLy8k8ycyNpB/1L2vP+kHDzmM6Pr0IvkFgnbIFQmXeS5NBV+xOdlAYzuPFkCy"+
												"fUSOKdmt3F/Pbf9EhQJBANrF5Uaxmk7qGXfRV7tCT+f27eAWtYi2h/gJenLrmtke"+
												"Hg7SkgDiYHErJDns85va4cnhaAzAI1eSIHVaXh3JGXcCQQDDL9ns78LNDr/QuHN9"+
												"pmeDdlQfikeDKzW8dMcUIqGVX4WQJMptviZuf3cMvgm9+hDTVLvSePdTlA9YSCF4"+
												"VNPbAkEAvbe54XlpCKBIX7iiLRkPdGiV1qu614j7FqUZlAkvKrPMeywuQygNXHZ+"+
												"HuGWTIUfItQfSFdjDrEBBuPMFGZtdwJAV5N3xyyIjfMJM4AfKYhpN333HrOvhHX1"+
												"xVnsHOew8lGKnvMy9Gx11+xPISN/QYMa24dQQo5OAm0TOXwbsF73MwJAHzqaKZPs"+
												"EN08JunWDOKs3ZS+92maJIm1YGdYf5ipB8/Bm3wElnJsCiAeRqYKmPpAMlCZ5x+Z"+
												"AsuC1sjcp2r7xw==";
	
	public static final String  clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCmzaI2K/Cpaig/8gjne0F7t3uE"+
													"7Kx3eLM914A2FhGWYGKiI1Q3KXJ5c7cKJoIzI/cUsXacgnPORjhmtJb2tXzWaRui"+
													"l2EtcbhWvRuxUW2gAqAi99U0b/LeEzZH0IUO3tku2ZLaslHj1mC5c7vIceY13a4h"+
													"K0SMdY1itatTXhHdzQIDAQAB";*/
	
	// 客户端 将原始私钥的转换成PKCS8格式的私钥
	public static final String clientPrivateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAM9mfM/BTr2IPPtB" + 
			"GyDYo1BkDbdBgfgDhvY+dFB22hF5t5aG1g1KW6CdQog7INM95YI3+vHMdlPvmkd8" + 
			"vEjcBlLkd0EWvRIV7wv5upGO8TJ+vYor4EaoR7sx47996pm/TZD5jSWGesRrhTI4" + 
			"CkbVGe4l06rfBZ8PRO2XKNpqGR8/AgMBAAECgYAkD5rV+LN7KuwHd7uCy4gh2zOz" + 
			"UFWLzPkzaYqJzxB9h19PceRX7TzfQVinHTjI4fM84ATm8/kDAR8fHOYT+QW0JddU" + 
			"Fjp+ilFHaXQV9Rjnou/U176sjCrXdNpiPude8MJ68VQezCyE5e/4TD66kvQDRpXb" + 
			"AGl5W909rZwjFZXaEQJBAOpalv3r4VulPCl3Oxriz0b/emj1F6njJBCqTc2pQL2g" + 
			"lOGhY3L3CyiRjiIBhFlIu6WTf8sp6PRmB8B7VIidHMcCQQDijpGS86LKsUvU8n7u" + 
			"1gD//mi8e1deYaIfXQFrYhWJyah084GMGtnN86h8DTwIJiiUfVR59Jvbacr4/M/1" + 
			"GUHJAkBF5e0hISifKAJwr7I+S6XdHDgLdAax0iCgo9r+21uG841UWsmJsatvVzKY" + 
			"a/Fom+vz77FvDDoCIyhuvZoyAQJjAkEAnv6g6Tl0cL1WU57PN/wV/ZHknQoOeZ0Z" + 
			"MtuJiHvwU5+jSlgt/U5GtoOeJVkAXVOyPOtr4p6o1qX7HRwHMaJFCQJBAONv+hwy" + 
			"VM7uRIdEqnnx7oMT4/+1XpwXqqZL6Qu69ULw6r8OtCiCRUzvLBr1nquWxhTastQ0" + 
			"X5uHQww065oHGwM=";

	// 客户端 公钥
	public static final String clientPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPZnzPwU69iDz7QRsg2KNQZA23" + 
			"QYH4A4b2PnRQdtoRebeWhtYNSlugnUKIOyDTPeWCN/rxzHZT75pHfLxI3AZS5HdB" + 
			"Fr0SFe8L+bqRjvEyfr2KK+BGqEe7MeO/feqZv02Q+Y0lhnrEa4UyOApG1RnuJdOq" + 
			"3wWfD0TtlyjaahkfPwIDAQAB";
	
	// 服务端 将原始私钥的转换成PKCS8格式的私钥
	public static final String  serverPrivateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIclo1lSxru9S6eg" + 
			"YImIZCzSsd5xkMAtKXput7Quw6yhZRbO4j1OFPhNHzBmZmVaqAUvr1C/dWgnmFui" + 
			"8NPa4uGz+5zWGWdcfyR0EQvyMamlPBA+6oo2UVLDgtPNKkz2eJy0UwWKN212Qz+H" + 
			"Z/vi85X+HjSjgUcJmwYz2h/2pjR3AgMBAAECgYAr0yS5XoJbdvMFlJg5gSUa8+gB" + 
			"/km2R+7faO/hWhjR7jRdxRDQWHWsXzXx+ALUcyVxKRls0ek8sTpS3O/Dg4N2t7bh" + 
			"bxO+bG7Ife5RSgXFBpN7K6jyt2O3kZDRY1BmajF2lXly3TGLN3ZtVvAXaTRoVt79" + 
			"b02Wx3iDT0tonfaHwQJBAPhLOqDNwmxO+IEMwaIiuBaCq4jzE+QQ3e80ubYxW7ly" + 
			"vqkNaHeXNxFVjeFKG3NS0d4YQD7U/QmBmqBsuXohH38CQQCLV2w08arQhFZj+UP/" + 
			"HwAOgFKm+ucdgm6xzQfHQUseL9N0147TpRL3lHK0XKG7wqs5CebsIQ+vcsR6JXaQ" + 
			"MGcJAkAVJOroOL1+1bbJ3pk6wnQkzpnm/rRJ7rnHnhjWkBt8jm34HYEw9fqlikCb" + 
			"1+DAkGP44t3Nu/uUbKoLUVb2NI3nAkAse7pFpKj9bGIQBHGarpDcEEdSm2LQ3uTr" + 
			"yiKjj8qlVmtRL8ee9WH6u99qiO/w+xKiYPDhjSRuxFrJC9Cv82PRAkEAmHyruGrN" + 
			"kDBgscTgtkXgQeAvXtBbo7aAEZQlO4MlYaJlpsYhsgriAjdugUdYjoLo7PMVVRcT" + 
			"YxkFhvp0UEtAZQ==";
	
	// 服务端 公钥
	public static final String  serverPublicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCHJaNZUsa7vUunoGCJiGQs0rHe" + 
			"cZDALSl6bre0LsOsoWUWzuI9ThT4TR8wZmZlWqgFL69Qv3VoJ5hbovDT2uLhs/uc" + 
			"1hlnXH8kdBEL8jGppTwQPuqKNlFSw4LTzSpM9nictFMFijdtdkM/h2f74vOV/h40" + 
			"o4FHCZsGM9of9qY0dwIDAQAB";
	
	public static void main(String[] args) throws Exception {
		TreeMap<String, Object> params = new TreeMap<String, Object>();
		params.put("userid", "152255855");
		params.put("phone", "18965621420");
		
		client(params);
		
		server();
	}
	
	public static void client(TreeMap<String, Object> params) throws Exception{
		// 生成RSA签名
		String sign = EncryUtil.handleRSA(params, clientPrivateKey);
		params.put("sign", sign);
		
		String info = JSON.toJSONString(params);
		System.out.println("info: ");
		System.out.println(info);
		System.out.println("=================================");
		//随机生成AES密钥
		String aesKey = RandomUtil.getRandom(16);
		System.out.println("aesKey: ");
		System.out.println(aesKey);
		System.out.println("=================================");
		//AES加密数据
		String data = AES.encryptToBase64(info, aesKey);
		System.out.println("data: ");
		System.out.println(data);
		System.out.println("=================================");
		//AES加密数据
		
		// 使用RSA算法将商户自己随机生成的AESkey加密
		String encryptkey = RSA.encrypt(aesKey, serverPublicKey);
		
		Req.data = data;
		Req.encryptkey = encryptkey;
		
		System.out.println("加密后的请求数据:\n" + new Req().toString());
	}
	
	public static void server() throws Exception {
		
		// 验签
		boolean passSign = EncryUtil.checkDecryptAndSign(Req.data,
					Req.encryptkey, clientPublicKey, serverPrivateKey);
		
		if(passSign){
			// 验签通过
			String aeskey = RSA.decrypt(Req.encryptkey,
						serverPrivateKey);
			String data = AES.decryptFromBase64(Req.data,
					aeskey);
			
			JSONObject jsonObj = JSONObject.parseObject(data);
			String userid = jsonObj.getString("userid");
			String phone = jsonObj.getString("phone");
			
			System.out.println("解密后的明文:userid:"+userid+" phone:"+phone);
			
		}else{
			System.out.println("验签失败");
		}
	}
	
	static class Req{
		public static String data;
		public static String encryptkey;
		
		@Override
		public String toString() {
			return "data:"+data+"\nencryptkey:"+encryptkey;
		}
	}
}
