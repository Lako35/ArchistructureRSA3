package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String[] SIGNATURE_ALGORITHMS = {
            "RSASSA-PSS", "SHA1WithRSA/PSS", "SHA224WithRSA/PSS", "SHA384WithRSA/PSS",
            "SHA1withRSAandMGF1", "SHA256withRSA", "SHA1withRSA", "SHA384withRSA",
            "SHA512withRSA", "MD2withRSA", "MD5withRSA"
    };

    public static void main(String[] args) throws Exception {
        // ensure required directories exist
        Files.createDirectories(Paths.get("keys"));
        Files.createDirectories(Paths.get("inputs"));

        Scanner scanner = new Scanner(System.in);
        System.out.print("Mode? (G)enerate Keypair / (S)ign / (V)erify / (E)ncrypt / (D)ecrypt\n"
                         + "S2 (using inputs/text) / V2 / E2 \nSF(ile) / VF / EF / DF\n"
                         + "**.E** (group‑encrypt text) / **.E2** (group‑encrypt text‑file) / **.EF** (group‑encrypt File): ");
        String mode = scanner.nextLine().trim().toUpperCase();

        switch (mode) {

            case ".E":
                doGroupEncrypt(scanner);
                break;

            case ".E2":
                doGroupEncryptFileText(scanner);
                break;
                
                
            case "G":
                generateKeypair(scanner);
                break;

            case "SIGN":
            case "S":
                doSign(scanner);
                break;

            case "SIGN2":
            case "S2":
                doSignFileText(scanner);
                break;

            case "VERIFY":
            case "V":
                doVerify(scanner);
                break;

            case "VERIFY2":
            case "V2":
                doVerifyFileText(scanner);
                break;

            case "ENCRYPT":
            case "E":
                doEncrypt(scanner);
                break;

            case "ENCRYPT2":
            case "E2":
                doEncryptFileText(scanner);
                break;

            case "DECRYPT":
            case "D":
                doDecrypt(scanner);
                break;

            case "SF":
                doSignBinaryFile(scanner);
                break;
            case ".EF":
                doEF(scanner);
                break;

            case "VF":
                doVerifyBinaryFile(scanner);
                break;

            case "EF":
                doEncryptBinaryFile(scanner);
                break;

            case "DF":
                doDecryptBinaryFile(scanner);
                break;

            default:
                System.out.println("Invalid mode. Please enter one of: "
                        + "G, S, S2, V, V2, E, E2, D, SF, VF, EF, DF.");
                break;
        }
        System.exit(0);
    }

    private static void generateKeypair(Scanner scanner) throws Exception {
        Path pubPath  = Paths.get("publickey.pem");
        Path privPath = Paths.get("privatekey.pem");
        if (Files.exists(pubPath) || Files.exists(privPath)) {
            System.out.print("WARNING: Key files already exist. "
                    + "Type CONFIRMCONFIRMCONFIRM to overwrite: ");
            if (!"CONFIRMCONFIRMCONFIRM".equals(scanner.nextLine().trim())) {
                System.out.println("Key generation aborted.");
                return;
            }
        }
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(4096);
        KeyPair pair = keyGen.generateKeyPair();
        String publicEncoded  = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        String privateEncoded = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());
        Files.writeString(pubPath,  publicEncoded);
        Files.writeString(privPath, privateEncoded);
        System.out.println("4096-bit RSA keypair generated successfully.");
        System.out.println("Saved to:\n" + pubPath + "\n" + privPath);
    }

    private static void doSign(Scanner scanner) throws Exception {
        PrivateKey key = getPrivateKey(scanner);
        System.out.print("Enter string to sign: ");
        String text = scanner.nextLine();
        String signedText = text + " | Signed at "
                + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        System.out.println("\nText to be signed:\n" + signedText);
        System.out.println("Digital Signature:\n" + signText(signedText, key));
    }

    private static void doSignFileText(Scanner scanner) throws Exception {
        PrivateKey key = getPrivateKey(scanner);
        String txt = readFileText();
        String signedText = txt + " | Signed at "
                + LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
        System.out.println("\nText from inputs/text to be signed:\n" + signedText);
        System.out.println("Digital Signature:\n" + signText(signedText, key));
    }

    private static void doVerify(Scanner scanner) throws Exception {
        System.out.print("Enter text to verify: ");
        String text = scanner.nextLine();
        System.out.print("Enter digital signature (Base64) to verify: ");
        String sigB64 = scanner.nextLine().trim();
        byte[] sig = Base64.getDecoder().decode(sigB64);

        // 1) Try every .pem in keys/
        File[] files = new File("keys").listFiles((d,n)->n.endsWith(".pem"));
        if (files != null) {
            for (File f : files) {
                String name = f.getName();
                try {
                    String raw = Files.readString(f.toPath())
                            .replaceAll("-----.*?-----", "")
                            .replaceAll("\\s+","");
                    byte[] keyBytes = Base64.getDecoder().decode(raw);
                    PublicKey pub = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(keyBytes));

                    boolean ok = false;
                    for (String alg : SIGNATURE_ALGORITHMS) {
                        try {
                            Signature s = Signature.getInstance(alg);
                            s.initVerify(pub);
                            s.update(text.getBytes());
                            if (s.verify(sig)) {
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));
                                System.out.println("verified with " + name + " using " + alg);
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));

                                return;
                            }
                        } catch (Exception ignore) {}
                    }
                    System.out.println("failed to verify with " + name + " with all signatures");
                } catch (Exception e) {
                    System.out.println("error loading key " + name + ": " + e.getMessage());
                }
            }
        }


        // 3) Finally, load and try the default publickey.pem
        PublicKey defaultPub = loadDefaultPublicKey();
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(defaultPub);
                s.update(text.getBytes(StandardCharsets.UTF_8));
                if (s.verify(sig)) {                    
                    System.out.println("-".repeat(("verified with publickey.pem using " + alg).length()));
                    System.out.println("verified with publickey.pem using " + alg);
                    System.out.println("-".repeat(("verified with publickey.pem using " + alg).length()));

                    return;
                }
            } catch (Exception ignore) {}
        }

        System.out.println("failed to verify with publickey.pem with all signatures");

        // 2) Finally, try the user's private key → derive its public half
        PublicKey pub = getPublicKey(scanner);


        boolean ok = false;
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(pub);
                s.update(text.getBytes());
                if (s.verify(sig)) {
                    System.out.println("-".repeat(("verified using " + alg).length()));
                    System.out.println("verified using " + alg);
                    System.out.println("-".repeat(("verified using " + alg).length()));

                    return;
                }
            } catch (Exception ignore) {}
        }
        System.err.println("failed to verify with all signatures");
    }


    private static void doVerifyFileText(Scanner scanner) throws Exception {
        String text = readFileText();
        System.out.println("Text from inputs/text to verify:\n" + text);
        System.out.print("Enter digital signature (Base64) to verify: ");
        String sigB64 = scanner.nextLine().trim();
        byte[] sig = Base64.getDecoder().decode(sigB64);

        // 2) Try every .pem in keys/
        File[] files = new File("keys").listFiles((d, n) -> n.endsWith(".pem"));
        if (files != null) {
            for (File f : files) {
                String name = f.getName();
                try {
                    String raw = Files.readString(f.toPath())
                            .replaceAll("-----.*?-----", "")
                            .replaceAll("\\s+", "");
                    byte[] keyBytes = Base64.getDecoder().decode(raw);
                    PublicKey pub = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(keyBytes));

                    for (String alg : SIGNATURE_ALGORITHMS) {
                        try {
                            Signature s = Signature.getInstance(alg);
                            s.initVerify(pub);
                            s.update(text.getBytes(StandardCharsets.UTF_8));
                            if (s.verify(sig)) {
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));
                                System.out.println("verified with " + name + " using " + alg);
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));

                                return;
                            }
                        } catch (Exception ignore) {}
                    }
                    System.out.println("failed to verify with " + name + " with all signatures");
                } catch (Exception e) {
                    System.out.println("error loading key " + name + ": " + e.getMessage());
                }
            }
        }

        // 3) Finally, load and try the default publickey.pem
        PublicKey defaultPub = loadDefaultPublicKey();
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(defaultPub);
                s.update(text.getBytes(StandardCharsets.UTF_8));
                if (s.verify(sig)) {
                    System.out.println("-".repeat(("verified with publickey.pem using " + alg).length()));
                    System.out.println("verified with publickey.pem using " + alg);
                    System.out.println("-".repeat(("verified with publickey.pem using " + alg).length()));

                    return;
                }
            } catch (Exception ignore) {}
        }

        System.out.println("failed to verify with publickey.pem with all signatures");

        PublicKey pub = getPublicKey(scanner);


        boolean ok = false;
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(pub);
                s.update(text.getBytes());
                if (s.verify(sig)) {
                    System.out.println("verified using " + alg);
                    return;
                }
            } catch (Exception ignore) {}
        }
        System.err.println("failed to verify with all signatures");
    }

    private static void doEncrypt(Scanner scanner) throws Exception {
        PublicKey key = getPublicKey(scanner);
        System.out.print("Enter text to encrypt: ");
        String text = scanner.nextLine();
        System.out.println("Encrypted Text:\n" + encryptText(text, key));
    }

    private static void doEncryptFileText(Scanner scanner) throws Exception {
        PublicKey key = getPublicKey(scanner);
        String txt = readFileText();
        System.out.println("Text from inputs/text to encrypt:\n" + txt);
        System.out.println("Encrypted Text:\n" + encryptText(txt, key));
    }
    private static void doDecrypt(Scanner scanner) throws Exception {
        // single prompt for both JSON‐envelope and legacy flows
        System.out.print("Enter text to decrypt: ");
        String input = scanner.nextLine().trim();

        if (input.startsWith("{")) {
            // ---- JSON envelope branch ----

            // 1) load this recipient’s keys
            PrivateKey priv = loadPrivateKey(Paths.get("privatekey.pem"));
            PublicKey  pub  = loadPublicKey (Paths.get("publickey.pem"));
            String myId = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(
                            MessageDigest.getInstance("SHA-256")
                                    .digest(pub.getEncoded())
                    );

            // 2) extract the keys[...] array
            Matcher keyArray = Pattern.compile("\"keys\"\\s*:\\s*\\[(.*?)\\]")
                    .matcher(input);
            if (!keyArray.find()) {
                System.err.println("Invalid envelope (no keys array).");
                return;
            }
            String keysContent = keyArray.group(1);

            // 3) find our wrapped session key
            SecretKeySpec sessKey = null;
            Matcher em = Pattern.compile(
                    "\\{\\s*\"id\"\\s*:\\s*\"([^\"]+)\"\\s*," +
                            "\\s*\"wrap\"\\s*:\\s*\"([^\"]+)\"\\s*}"
            ).matcher(keysContent);
            while (em.find()) {
                if (em.group(1).equals(myId)) {
                    byte[] wrapped = Base64.getDecoder().decode(em.group(2));
                    Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                    rsa.init(Cipher.DECRYPT_MODE, priv);
                    byte[] sk = rsa.doFinal(wrapped);
                    sessKey = new SecretKeySpec(sk, "AES");
                    break;
                }
            }
            if (sessKey == null) {
                System.err.println("No matching key for this recipient.");
                return;
            }

            // 4) pull out the payload (iv||ciphertext base64)
            Matcher pm = Pattern.compile("\"payload\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"")
                    .matcher(input);
            if (!pm.find()) {
                System.err.println("Invalid envelope (no payload).");
                return;
            }
            byte[] combined = Base64.getDecoder().decode(pm.group(1));
            ByteBuffer bb = ByteBuffer.wrap(combined);
            byte[] iv = new byte[16];
            bb.get(iv);
            byte[] ct = new byte[bb.remaining()];
            bb.get(ct);

            // 5) AES‐decrypt
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
            aes.init(Cipher.DECRYPT_MODE, sessKey, new IvParameterSpec(iv));
            byte[] plain = aes.doFinal(ct);

            System.out.println("Decrypted text:\n"
                    + new String(plain, StandardCharsets.UTF_8));
            return;
        }

        // ---- Legacy fallback branch ----
        // Reuse the same 'input' from above
        PrivateKey key = getPrivateKey(scanner);
        String plain = decryptText(input, key);
        System.out.println("Decrypted text:\n" + plain);
    }

    
    
    private static void doSignBinaryFile(Scanner scanner) throws Exception {
        PrivateKey key = getPrivateKey(scanner);
        String filename = selectInputFile(scanner);
        byte[] data = readBinaryFile(filename);
        String signature = Base64.getEncoder().encodeToString(signBytes(data, key));
        System.out.println("Signature (Base64):\n" + signature);
    }

    private static void doVerifyBinaryFile(Scanner scanner) throws Exception {
        String filename = selectInputFile(scanner);
        System.out.print("Enter signature (Base64) to verify: ");
        String sigB64 = scanner.nextLine().trim();
        byte[] sig = Base64.getDecoder().decode(sigB64);
        byte[] data = readBinaryFile(filename);

        File[] files = new File("keys").listFiles((d, n) -> n.endsWith(".pem"));
        if (files != null) {
            for (File f : files) {
                String name = f.getName();
                try {
                    String raw = Files.readString(f.toPath(), StandardCharsets.UTF_8)
                            .replaceAll("-----.*?-----", "")
                            .replaceAll("\\s+", "");
                    byte[] keyBytes = Base64.getDecoder().decode(raw);
                    PublicKey pub = KeyFactory.getInstance("RSA")
                            .generatePublic(new X509EncodedKeySpec(keyBytes));

                    for (String alg : SIGNATURE_ALGORITHMS) {
                        try {
                            Signature s = Signature.getInstance(alg);
                            s.initVerify(pub);
                            s.update(data);
                            if (s.verify(sig)) {
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));
                                System.out.println("verified with " + name + " using " + alg);
                                System.out.println("-".repeat(("verified with " + name + " using " + alg).length()));

                                return;
                            }
                        } catch (Exception ignore) {}
                    }
                    System.out.println("failed to verify with " + name + " with all signatures");
                } catch (Exception e) {
                    System.out.println("error loading key " + name + ": " + e.getMessage());
                }
            }
        }

        // 3) Finally, load and try the default publickey.pem
        PublicKey defaultPub = loadDefaultPublicKey();
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(defaultPub);
                s.update(data);
                if (s.verify(sig)) {
                    System.out.println("-".repeat(("verified with publickey.pem using" + alg).length()));
                    System.out.println("verified with publickey.pem using " + alg);
                    System.out.println("-".repeat(("verified with publickey.pem using" + alg).length()));

                    return;
                }
            } catch (Exception ignore) {}
        }

        System.out.println("failed to verify with publickey.pem with all signatures");

        // Try user's private key last
        PublicKey pub = getPublicKey(scanner);


        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                Signature s = Signature.getInstance(alg);
                s.initVerify(pub);
                s.update(data);
                if (s.verify(sig)) {
                    System.out.println("verified using " + alg);
                    return;
                }
            } catch (Exception ignore) {}
        }
        System.err.println("failed to verify with all signatures");
    }


    private static void doEncryptBinaryFile(Scanner scanner) throws Exception {
        PublicKey key = getPublicKey(scanner);
        String filename = selectInputFile(scanner);
        encryptFileWithHybridRSA(filename, key);
        System.out.println("File encrypted successfully.");
    }

    private static void doDecryptBinaryFile(Scanner scanner) throws Exception {



        File inputDir = new File("inputs");
        File[] candidates = inputDir.listFiles(f -> f.isFile());
        if (candidates == null || candidates.length == 0) {
            System.err.println("No files found in inputs/");
            return;
        }
        System.out.println("Select file to decrypt:");
        for (int i = 0; i < candidates.length; i++) {
            System.out.printf("  %d) %s%n", i, candidates[i].getName());
        }
        System.out.print("Enter number: ");
        int choice = Integer.parseInt(scanner.nextLine().trim());
        if (choice < 0 || choice >= candidates.length) {
            System.err.println("Invalid selection.");
            return;
        }
        Path inPath = candidates[choice].toPath();

        // 1) Open & peek first byte
        try (InputStream fis = Files.newInputStream(inPath);
             BufferedInputStream bis = new BufferedInputStream(fis)) {

            bis.mark(1);
            int first = bis.read();
            bis.reset();

            if (first == '{') {
                // ---- .EF branch ----
                EFHeader header = parseEFHeader(bis);

                // load this recipient’s keys
                PrivateKey priv = loadPrivateKey(Paths.get("privatekey.pem"));
                PublicKey pub   = loadPublicKey(Paths.get("publickey.pem"));
                String myId = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(
                                MessageDigest.getInstance("SHA-256")
                                        .digest(pub.getEncoded())
                        );

                // find & unwrap the session key
                SecretKeySpec sessKey = null;
                for (EFKeyEntry e : header.keys) {
                    if (e.id.equals(myId)) {
                        byte[] wrapped = Base64.getDecoder().decode(e.wrap);
                        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        rsa.init(Cipher.DECRYPT_MODE, priv);
                        byte[] sk = rsa.doFinal(wrapped);
                        sessKey = new SecretKeySpec(sk, "AES");
                        break;
                    }
                }
                if (sessKey == null) {
                    System.err.println("No matching key for this recipient.");
                    return;
                }

                // now decrypt the remainder of the stream
                Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
                aes.init(Cipher.DECRYPT_MODE, sessKey, new IvParameterSpec(header.iv));

                Path outPath = Paths.get("inputs", removePrefix(header.fileName));
                try (CipherInputStream cis = new CipherInputStream(bis, aes);
                     OutputStream       fos = Files.newOutputStream(outPath)) {
                    byte[] buf = new byte[8192];
                    int    r;
                    while ((r = cis.read(buf)) != -1) {
                        fos.write(buf, 0, r);
                    }
                }

                System.out.println("Decrypted file written to: " + outPath);
                return;
            }
        }
        
        
        
        PrivateKey key = getPrivateKey(scanner);
        String filename = inPath.getFileName().toString();

        decryptFileWithHybridRSA(filename, key);
        System.out.println("File decrypted successfully.");
    }

    private static PrivateKey getPrivateKey(Scanner scanner) throws Exception {
        // 1) discover all .pem in keys/ that actually parse as an RSA private key
        List<String> valid = new ArrayList<>();
        File dir = new File("keys");
        File[] all = dir.listFiles((d,n)->n.endsWith(".pem"));
        if (all!=null) for(File f:all){
            try {
                String raw = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8)
                        .replaceAll("-----.*?-----","")
                        .replaceAll("\\s+","");
                byte[] kb = Base64.getDecoder().decode(raw);
                KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(kb));
                valid.add(f.getName());
            } catch(Exception ignored){}
        }

        // 2) print menu
        if(!valid.isEmpty()){
            System.out.println("Available private key files:");
            System.out.println(". - default (privatekey.pem)");
            for(int i=0;i<valid.size();i++){
                System.out.printf("%d - %s%n", i+1, valid.get(i));
            }
        } else {
            System.out.println("No valid private keys found in keys/");
        }

        System.out.print("Enter number to select, '.' for default, or paste Base64: ");
        String sel = scanner.nextLine().trim();
        String content;

        if(".".equals(sel)){
            content = new String(Files.readAllBytes(Paths.get("privatekey.pem")), StandardCharsets.UTF_8);
        } else {
            try {
                int idx = Integer.parseInt(sel) - 1;
                if(idx>=0 && idx<valid.size()){
                    content = new String(Files.readAllBytes(
                            Paths.get("keys", valid.get(idx))), StandardCharsets.UTF_8);
                } else {
                    content = sel;
                }
            } catch(NumberFormatException e){
                content = sel;
            }
        }

        // strip PEM armor & whitespace
        content = content
                .replace("-----BEGIN RSA PRIVATE KEY-----","")
                .replace("-----END RSA PRIVATE KEY-----","")
                .replaceAll("\\s+","");

        byte[] keyBytes = Base64.getDecoder().decode(content);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }


    private static PublicKey getPublicKey(Scanner scanner) throws Exception {
        // 1) discover all .pem in keys/ that actually parse as an RSA public key
        List<String> valid = new ArrayList<>();
        File dir = new File("keys");
        File[] all = dir.listFiles((d,n)->n.endsWith(".pem"));
        if (all!=null) for(File f:all){
            try {
                String raw = new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8)
                        .replaceAll("-----.*?-----","")
                        .replaceAll("\\s+","");
                byte[] kb = Base64.getDecoder().decode(raw);
                KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(kb));
                valid.add(f.getName());
            } catch(Exception ignored){}
        }

        // 2) print menu
        if(!valid.isEmpty()){
            System.out.println("Available public key files:");
            System.out.println(". - default (publickey.pem)");
            for(int i=0;i<valid.size();i++){
                System.out.printf("%d - %s%n", i+1, valid.get(i));
            }
        } else {
            System.out.println("No valid public keys found in keys/");
        }

        System.out.print("Enter number to select, '.' for default, or paste Base64: ");
        String sel = scanner.nextLine().trim();
        String content;

        if(".".equals(sel)){
            content = new String(Files.readAllBytes(Paths.get("publickey.pem")), StandardCharsets.UTF_8);
        } else {
            try {
                int idx = Integer.parseInt(sel) - 1;
                if(idx>=0 && idx<valid.size()){
                    content = new String(Files.readAllBytes(
                            Paths.get("keys", valid.get(idx))), StandardCharsets.UTF_8);
                } else {
                    content = sel;
                }
            } catch(NumberFormatException e){
                content = sel;
            }
        }

        // strip PEM armor & whitespace
        content = content
                .replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","")
                .replaceAll("\\s+","");

        byte[] keyBytes = Base64.getDecoder().decode(content);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }



    /**
     * Lists files in inputs directory, then:
     *  1) pick by number
     *  2) or type filename manually
     */
    private static String selectInputFile(Scanner scanner) {
        String[] files = new File("inputs").list((dir, name) -> new File(dir, name).isFile());

        if (files != null && files.length > 0) {
            System.out.println("Available input files:");
            for (int i = 0; i < files.length; i++) {
                System.out.println((i + 1) + " - " + files[i]);
            }
        } else {
            System.out.println("No files found in 'inputs' directory.");
        }

        System.out.print("Enter number to select file or type filename manually: ");
        String input = scanner.nextLine().trim();
        try {
            int idx = Integer.parseInt(input);
            if (files != null && idx >= 1 && idx <= files.length) {
                return files[idx - 1];
            }
        } catch (NumberFormatException ignored) {}
        return input;
    }

    private static String signText(String text, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(text.getBytes());
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    private static boolean verifySignature(
            String text, String signatureStr, PublicKey publicKey, String alg
    ) throws Exception {
        Signature sig = Signature.getInstance(alg);
        sig.initVerify(publicKey);
        sig.update(text.getBytes());
        return sig.verify(Base64.getDecoder().decode(signatureStr));
    }

    private static String tryAllSignatureAlgorithms(
            String text, String sig, PublicKey pub
    ) {
        for (String alg : SIGNATURE_ALGORITHMS) {
            try {
                if (verifySignature(text, sig, pub, alg)) {
                    return "Signature verified successfully using: " + alg;
                }
            } catch (Exception ignored) {}
        }
        return "Signature verification failed with all known algorithms.";
    }

    private static String encryptText(String text, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] in = text.getBytes();
        int bs = 501, offset = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (offset < in.length) {
            int len = Math.min(bs, in.length - offset);
            out.write(cipher.doFinal(in, offset, len));
            offset += len;
        }
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    private static String decryptText(String enc, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] in = Base64.getDecoder().decode(enc);
        int bs = 512, offset = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (offset < in.length) {
            int len = Math.min(bs, in.length - offset);
            out.write(cipher.doFinal(in, offset, len));
            offset += len;
        }
        return out.toString();
    }

    private static String readFileText() throws IOException {
        System.out.println("Reading in...");
        Path p = Paths.get("inputs", "text.txt");
        if (!Files.exists(p)) throw new FileNotFoundException("inputs/text not found");
        String temp = Files.readString(p);
        System.out.println("Done reading " + "(" + temp.length() + ")");
        System.out.print("Contents: " + temp + "(" + temp.length() + ")\n");
        return temp;
        
    }

    private static byte[] readBinaryFile(String filename) {
        try {
            return Files.readAllBytes(Paths.get("inputs", filename));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] signBytes(byte[] data, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }


    static void encryptFileWithHybridRSA(String filename, PublicKey publicKey)
            throws Exception {
        Path inPath  = Paths.get("inputs", filename);
        Path outPath = Paths.get("inputs", "ENCRYPTED-" + filename);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();
        byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        Cipher aesC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesC.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);

        Cipher rsaC = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaC.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encKey = rsaC.doFinal(aesKey.getEncoded());

        try (OutputStream os = Files.newOutputStream(outPath);
             CipherOutputStream cos = new CipherOutputStream(os, aesC);
             InputStream is = Files.newInputStream(inPath)) {
            os.write(encKey);
            os.write(iv);
            byte[] buf = new byte[8192];
            int r;
            while ((r = is.read(buf)) != -1) cos.write(buf, 0, r);
        }
    }

    static void decryptFileWithHybridRSA(String filename, PrivateKey privateKey)
            throws Exception {
        byte[] all = Files.readAllBytes(
                Paths.get("inputs", filename)
        );
        int rsaLen = 512, ivLen = 16;
        byte[] encKey = Arrays.copyOfRange(all, 0, rsaLen);
        byte[] iv     = Arrays.copyOfRange(all, rsaLen, rsaLen + ivLen);
        byte[] body   = Arrays.copyOfRange(all, rsaLen + ivLen, all.length);

        Cipher rsaC = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaC.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] aesKeyBytes = rsaC.doFinal(encKey);

        SecretKey aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        Cipher aesC = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aesC.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
        byte[] decoded = aesC.doFinal(body);

        Path outPath = Paths.get("inputs", "DECRYPTED-" + filename.replace("ENCRYPTED-", ""));
        Files.write(outPath, decoded);
    }



    private static void doGroupEncrypt(Scanner scanner) throws Exception {
        // 1) Discover recipient public-key PEMs (including default)
        List<String> names = new ArrayList<>();
        names.add(".");  // index 0 → your default publickey.pem

        File dir = new File("keys");
        File[] all = dir.listFiles((d, n) -> n.endsWith(".pem"));
        if (all != null) {
            for (File f : all) {
                try {
                    String pem = Files.readString(f.toPath(), StandardCharsets.UTF_8)
                            .replaceAll("-----.*?-----", "")
                            .replaceAll("\\s+", "");
                    byte[] keyBytes = Base64.getDecoder().decode(pem);
                    // X.509 test
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory.getInstance("RSA").generatePublic(spec);
                    names.add(f.getName());
                } catch (Exception ignored) {
                    // not a valid public-key PEM, skip
                }
            }
        }

        // 2) Prompt for recipients
        System.out.println("Available recipient public-key files:");
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equals(".")) {
                System.out.println("0) . – default publickey.pem");
            } else {
                System.out.printf("%d) %s%n", i, names.get(i));
            }
        }
        System.out.print("Enter CSV of recipients (e.g. 0,2,3): ");
        String line = scanner.nextLine().trim();
        if (line.isEmpty()) {
            System.out.println("No recipients specified. Aborting.");
            System.exit(1);
        }

        // 3) Load each recipient’s PublicKey
        List<PublicKey> recipients = new ArrayList<>();
        for (String tok : line.split("\\s*,\\s*")) {
            int idx;
            try { idx = Integer.parseInt(tok); }
            catch (NumberFormatException e) { idx = -1; }
            if (idx < 0 || idx >= names.size()) {
                System.out.println("Invalid recipient index: " + tok);
                System.exit(1);
            }
            Path pemPath = names.get(idx).equals(".")
                    ? Paths.get("publickey.pem")
                    : Paths.get("keys", names.get(idx));
            String raw = Files.readString(pemPath, StandardCharsets.UTF_8)
                    .replaceAll("-----.*?-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(raw);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            PublicKey rpub = KeyFactory.getInstance("RSA").generatePublic(spec);
            recipients.add(rpub);
        }

        // 4) Read plaintext to encrypt
        System.out.print("Enter text to group-encrypt: ");
        String message = scanner.nextLine();
        byte[] plain = message.getBytes(StandardCharsets.UTF_8);

        // 5–6) Generate session AES key and IV
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sessKey = kg.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        // 7) Encrypt the plaintext with AES
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, sessKey, new IvParameterSpec(iv));
        byte[] cipherBytes = aes.doFinal(plain);
        String payloadB64 = Base64.getEncoder()
                .encodeToString(ByteBuffer.allocate(iv.length + cipherBytes.length)
                        .put(iv).put(cipherBytes).array());

        // 8) Wrap the session key for each recipient’s public key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        List<String> entries = new ArrayList<>();
        for (PublicKey rpub : recipients) {
            byte[] fp = sha256.digest(rpub.getEncoded());
            String id = Base64.getUrlEncoder().withoutPadding().encodeToString(fp);

            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, rpub);
            byte[] wrap = rsa.doFinal(sessKey.getEncoded());
            String wrapB64 = Base64.getEncoder().encodeToString(wrap);

            entries.add("{\"id\":\"" + id + "\",\"wrap\":\"" + wrapB64 + "\"}");
        }

        // 9) Emit JSON envelope
        String json = "{\"keys\":[" + String.join(",", entries) +
                "],\"payload\":\"" + payloadB64 + "\"}";
        System.out.println("\nGroup-encrypted JSON:");
        System.out.println(json);
    }


    private static void doGroupEncryptFileText(Scanner scanner) throws Exception {
        // Steps 1–3 identical to doGroupEncrypt (public-key discovery & loading)
        List<String> names = new ArrayList<>();
        names.add(".");  // index 0 → your default publickey.pem

        File dir = new File("keys");
        File[] all = dir.listFiles((d, n) -> n.endsWith(".pem"));
        if (all != null) {
            for (File f : all) {
                try {
                    String pem = Files.readString(f.toPath(), StandardCharsets.UTF_8)
                            .replaceAll("-----.*?-----", "")
                            .replaceAll("\\s+", "");
                    byte[] keyBytes = Base64.getDecoder().decode(pem);
                    // X.509 test
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory.getInstance("RSA").generatePublic(spec);
                    names.add(f.getName());
                } catch (Exception ignored) {}
            }
        }

        System.out.println("Available recipient public-key files:");
        for (int i = 0; i < names.size(); i++) {
            if (names.get(i).equals(".")) {
                System.out.println("0) . – default publickey.pem");
            } else {
                System.out.printf("%d) %s%n", i, names.get(i));
            }
        }
        System.out.print("Enter CSV of recipients (e.g. 0,2,3): ");
        String line = scanner.nextLine().trim();
        if (line.isEmpty()) {
            System.out.println("No recipients specified. Aborting.");
            System.exit(1);
        }

        List<PublicKey> recipients = new ArrayList<>();
        for (String tok : line.split("\\s*,\\s*")) {
            int idx;
            try { idx = Integer.parseInt(tok); }
            catch (NumberFormatException e) { idx = -1; }
            if (idx < 0 || idx >= names.size()) {
                System.out.println("Invalid recipient index: " + tok);
                System.exit(1);
            }
            Path pemPath = names.get(idx).equals(".")
                    ? Paths.get("publickey.pem")
                    : Paths.get("keys", names.get(idx));
            String raw = Files.readString(pemPath, StandardCharsets.UTF_8)
                    .replaceAll("-----.*?-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(raw);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            PublicKey rpub = KeyFactory.getInstance("RSA").generatePublic(spec);
            recipients.add(rpub);
        }

        // Step 4: read text file contents
        String message = readFileText();
        byte[] plain = message.getBytes(StandardCharsets.UTF_8);

        // Steps 5–8: same as above (AES key, encrypt payload, wrap session key)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sessKey = kg.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, sessKey, new IvParameterSpec(iv));
        byte[] cipherBytes = aes.doFinal(plain);
        String payloadB64 = Base64.getEncoder()
                .encodeToString(ByteBuffer.allocate(iv.length + cipherBytes.length)
                        .put(iv).put(cipherBytes).array());

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        List<String> entries = new ArrayList<>();
        for (PublicKey rpub : recipients) {
            byte[] fp = sha256.digest(rpub.getEncoded());
            String id = Base64.getUrlEncoder().withoutPadding().encodeToString(fp);

            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, rpub);
            byte[] wrap = rsa.doFinal(sessKey.getEncoded());
            String wrapB64 = Base64.getEncoder().encodeToString(wrap);

            entries.add("{\"id\":\"" + id + "\",\"wrap\":\"" + wrapB64 + "\"}");
        }

        String json = "{\"keys\":[" + String.join(",", entries) +
                "],\"payload\":\"" + payloadB64 + "\"}";
        System.out.println("\nGroup-encrypted JSON:");
        System.out.println(json);
    }



    private static PublicKey loadDefaultPublicKey() throws Exception {
        String pem = Files.readString(Paths.get("publickey.pem"), StandardCharsets.UTF_8);
        String b64 = pem.replaceAll("-----.*?-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }













    public static void doEF(Scanner scanner) throws Exception {
        // 1) Discover public-key PEMs
        List<String> names = new ArrayList<>();
        names.add(".");  // index 0 → default publickey.pem
        File keysDir = new File("keys");
        if (keysDir.isDirectory()) {
            for (File f : Objects.requireNonNull(keysDir.listFiles((d, n)->n.endsWith(".pem")))) {
                String pem = Files.readString(f.toPath(), StandardCharsets.UTF_8)
                        .replaceAll("-----.*?-----", "")
                        .replaceAll("\\s+", "");
                try {
                    byte[] der = Base64.getDecoder().decode(pem);
                    X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
                    KeyFactory.getInstance("RSA").generatePublic(spec);
                    names.add(f.getName());
                } catch (Exception ignored) {
                    // not a valid public-key PEM
                }
            }
        }

        // 2) Prompt for recipients
        System.out.println("Available recipient public-key files:");
        for (int i = 0; i < names.size(); i++) {
            String label = names.get(i).equals(".") ? "default publickey.pem" : names.get(i);
            System.out.printf("%d) %s%n", i, label);
        }
        System.out.print("Enter CSV of recipient indices: ");
        String line = scanner.nextLine().trim();
        if (line.isEmpty()) {
            System.out.println("No recipients specified. Aborting.");
            return;
        }

        // 3) Load each recipient’s PublicKey
        List<PublicKey> recipients = new ArrayList<>();
        for (String tok : line.split("\\s*,\\s*")) {
            int idx = Integer.parseInt(tok);
            if (idx < 0 || idx >= names.size()) {
                System.err.println("Invalid index: " + tok);
                return;
            }
            Path pemPath = names.get(idx).equals(".")
                    ? Paths.get("publickey.pem")
                    : Paths.get("keys", names.get(idx));
            String raw = Files.readString(pemPath, StandardCharsets.UTF_8)
                    .replaceAll("-----.*?-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(raw);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            recipients.add(KeyFactory.getInstance("RSA").generatePublic(spec));
        }

        // 4) Prompt for file
        File inputDir = new File("inputs");
        File[] candidates = inputDir.listFiles(f -> f.isFile());
        if (candidates == null || candidates.length == 0) {
            System.err.println("No files found in inputs/");
            return;
        }
        System.out.println("Select file to encrypt:");
        for (int i = 0; i < candidates.length; i++) {
            System.out.printf("  %d) %s%n", i, candidates[i].getName());
        }
        System.out.print("Enter number: ");
        int choice = Integer.parseInt(scanner.nextLine().trim());
        if (choice < 0 || choice >= candidates.length) {
            System.err.println("Invalid selection.");
            return;
        }
        Path inPath = candidates[choice].toPath();
        String filename = inPath.getFileName().toString();
        Path outPath = Paths.get("inputs", "ENCRYPTED-" + filename  );


        // 5) Generate AES session key + IV
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sessKey = kg.generateKey();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        // 6) Wrap session key under each recipient’s public key
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        List<String> entries = new ArrayList<>();
        for (PublicKey rpub : recipients) {
            // fingerprint
            String id = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(sha256.digest(rpub.getEncoded()));
            // RSA wrap
            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsa.init(Cipher.ENCRYPT_MODE, rpub);
            String wrapB64 = Base64.getEncoder()
                    .encodeToString(rsa.doFinal(sessKey.getEncoded()));
            entries.add("{\"id\":\"" + id + "\",\"wrap\":\"" + wrapB64 + "\"}");
        }

        // 7) Build JSON header
        long plainLen   = Files.size(inPath);
        String ivB64    = Base64.getEncoder().encodeToString(iv);
        String headerJson = "{"
                + "\"keys\":[" + String.join(",", entries) + "],"
                + "\"fileName\":\"" + filename + "\","
                + "\"iv\":\"" + ivB64 + "\","
                + "\"fileLength\":" + plainLen
                + "}";

        // 8) Write header + newline, then stream-encrypt file
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
        aes.init(Cipher.ENCRYPT_MODE, sessKey, ivSpec);

        try (OutputStream fos = Files.newOutputStream(outPath);
             FileInputStream fis = new FileInputStream(inPath.toFile());
             CipherOutputStream cos = new CipherOutputStream(fos, aes)) {

            // header
            fos.write(headerJson.getBytes(StandardCharsets.UTF_8));
            fos.write('\n');

            // ciphertext
            byte[] buf = new byte[8192];
            int r;
            while ((r = fis.read(buf)) != -1) {
                cos.write(buf, 0, r);
            }
        }

        System.out.println("Encrypted file written to: " + outPath);
    }








    private static EFHeader parseEFHeader(InputStream in) throws Exception {
        // read header up through first newline
        ByteArrayOutputStream hdr = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n') break;
            hdr.write(b);
        }
        String headerJson = hdr.toString(StandardCharsets.UTF_8.name());

        EFHeader header = new EFHeader();

        // fileName
        Matcher fn = Pattern.compile("\"fileName\"\\s*:\\s*\"([^\"]+)\"").matcher(headerJson);
        if (fn.find()) header.fileName = fn.group(1);

        // iv
        Matcher ivm = Pattern.compile("\"iv\"\\s*:\\s*\"([A-Za-z0-9+/=]+)\"").matcher(headerJson);
        if (ivm.find()) header.iv = Base64.getDecoder().decode(ivm.group(1));

        // keys array
        Matcher ka = Pattern.compile("\"keys\"\\s*:\\s*\\[(.*?)]").matcher(headerJson);
        if (ka.find()) {
            String keysContent = ka.group(1);
            Matcher em = Pattern.compile(
                    "\\{\\s*\"id\"\\s*:\\s*\"([^\"]+)\"\\s*," +
                            "\\s*\"wrap\"\\s*:\\s*\"([^\"]+)\"\\s*}"
            ).matcher(keysContent);
            while (em.find()) {
                header.keys.add(new EFKeyEntry(em.group(1), em.group(2)));
            }
        }

        return header;
    }

    private static PublicKey loadPublicKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8)
                .replaceAll("-----.*?-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(pem);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static PrivateKey loadPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8)
                .replaceAll("-----.*?-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String removePrefix(String name) {
        if (name.startsWith("ENCRYPTED-")) {
            return "DECRYPTED-" + name.substring("ENCRYPTED-".length());
        } else {
            return "DECRYPTED-" + name;
        }
    }

    private static class EFHeader {
        List<EFKeyEntry> keys    = new ArrayList<>();
        String           fileName;
        byte[]           iv;
    }

    private record EFKeyEntry(String id, String wrap) {
    }


}
