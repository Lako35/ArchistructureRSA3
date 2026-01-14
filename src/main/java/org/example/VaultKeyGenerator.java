package org.example;

import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class VaultKeyGenerator {

    public static void main(String[] args) throws Exception {
        System.out.print("whats ur password:");
        Scanner s = new Scanner(System.in);
        String password = s.nextLine(); // change this

        int iter = 600_000;
        byte[] salt = new byte[16];
        byte[] iv   = new byte[12];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        // random 32-byte DEK
        byte[] dek = new byte[32];
        new SecureRandom().nextBytes(dek);

        // derive KEK
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iter, 256);
        byte[] kekBytes = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(spec).getEncoded();
        SecretKeySpec kek = new SecretKeySpec(kekBytes, "AES");

        // encrypt DEK under KEK using AES-GCM
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, kek, new GCMParameterSpec(128, iv));
        byte[] ct = aes.doFinal(dek);

        // build JSON
        JSONObject obj = new JSONObject();
        obj.put("v", 1);
        obj.put("kdf", "PBKDF2WithHmacSHA256");
        obj.put("iter", iter);
        obj.put("salt", Base64.getEncoder().encodeToString(salt));
        obj.put("iv", Base64.getEncoder().encodeToString(iv));
        obj.put("ct", Base64.getEncoder().encodeToString(ct));

        String outB64 = Base64.getEncoder().encodeToString(obj.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println(outB64);
    }
}
