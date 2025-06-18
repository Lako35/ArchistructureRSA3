package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.json.JSONArray;
import org.json.JSONObject;


import java.io.*;
import java.nio.file.DirectoryStream;
import java.util.List;
import java.util.ArrayList;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.SwingWorker;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.ArrayList;
import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.Random;


public class CryptoGui extends JFrame {


    
    
private JTextField selectedFileField;
private JButton   selectFileBtn;
private JTextArea fileOpPublicKeyArea;
private JButton   browseFileOpPublicBtn;
private JTextArea fileOpPrivateKeyArea;
private JButton   browseFileOpPrivateBtn;
    private JTextField       digitalSignatureField;
    private JTextArea encryptPublicKeyArea;
    private JButton   browseEncryptBtn;
    private JTextArea encryptInputArea;
    private JTextArea encryptOutputArea;
    
    
    private CardLayout cardLayout;
    private JPanel cardPanel;

    // Generate tab fields
    private JTextArea privateKeyArea;
    private JTextArea publicKeyArea;
    private JRadioButton pemRadio;
    private JRadioButton base64Radio;


    private static final String[] SIGNATURE_ALGORITHMS = {
            "RSASSA-PSS", "SHA1WithRSA/PSS", "SHA224WithRSA/PSS", "SHA384WithRSA/PSS",
            "SHA1withRSAandMGF1", "SHA256withRSA", "SHA1withRSA", "SHA384withRSA",
            "SHA512withRSA", "MD2withRSA", "MD5withRSA"
    };

    private JTextArea decryptPrivateKeyArea;
    private JButton   browseDecryptBtn;
    private JTextArea decryptInputArea;
    private JTextArea decryptOutputArea;

    // Bottom status
    private JLabel statusBar;
    private JTextField mostRecentField;

    // Sign tab fields
    private JTextArea signPrivateKeyArea;
    private JButton browseSignBtn;
    private JTextField stuffToSignField;
    private JTextArea  stuffToSignArea;
    private JButton addTimestampBtn;
    private JButton signNowBtn;
    
    
        private JTextArea textToVerifyArea;
    private JTextArea verifyPublicKeyArea;
    private JTextField signatureField;



    public static void encryptFileWithHybridRSA(String inputPath, PublicKey pub) throws Exception {
        Path in  = Paths.get(inputPath);
        Path dir = in.getParent();
        String name = in.getFileName().toString();

        byte[] fileBytes = Files.readAllBytes(in);

        // 1) generate AES key
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey aesKey = kg.generateKey();

        // 2) encrypt data with AES/GCM
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        aes.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        byte[] cipherText = aes.doFinal(fileBytes);

        // 3) wrap AES key with RSA
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());

        // 4) write out: [len][wrappedKey][len][iv][cipherText]
        Path out = dir.resolve("ENCRYPTED-" + name);
        try (DataOutputStream dos = new DataOutputStream(Files.newOutputStream(out))) {
            dos.writeInt(wrappedKey.length);
            dos.write(wrappedKey);
            dos.writeInt(iv.length);
            dos.write(iv);
            dos.write(cipherText);
        }
    }

    public static void decryptFileWithHybridRSA(String inputPath, PrivateKey priv) throws Exception {
        Path in  = Paths.get(inputPath);
        Path dir = in.getParent();
        String name = in.getFileName().toString();

        byte[] all = Files.readAllBytes(in);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(all));

        // 1) read wrapped key
        int keyLen = dis.readInt();
        byte[] wrappedKey = new byte[keyLen];
        dis.readFully(wrappedKey);

        // 2) read IV
        int ivLen = dis.readInt();
        byte[] iv = new byte[ivLen];
        dis.readFully(iv);

        // 3) rest is ciphertext
        byte[] cipherText = new byte[all.length - 4 - keyLen - 4 - ivLen];
        dis.readFully(cipherText);

        // 4) unwrap AES key
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.DECRYPT_MODE, priv);
        byte[] aesBytes = rsa.doFinal(wrappedKey);
        SecretKeySpec aesKey = new SecretKeySpec(aesBytes, "AES");

        // 5) decrypt with AES/GCM
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        aes.init(Cipher.DECRYPT_MODE, aesKey, spec);
        byte[] plain = aes.doFinal(cipherText);

        // 6) write out
        Path out = dir.resolve("DECRYPTED-" + name);
        Files.write(out, plain);
    }

    private JPanel createFileOperationsPanel() {
        JPanel panel = new JPanel(new BorderLayout(8,8));

        // ── Input File chooser ─────────────────────────────────────────
        JPanel top = new JPanel(new BorderLayout(4,4));
        selectedFileField = new JTextField();
        JButton browseFileBtn = new JButton("Browse File…");
        browseFileBtn.addActionListener(e -> {
            JFileChooser fc = new JFileChooser(Paths.get("inputs").toFile());
            if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                selectedFileField.setText(fc.getSelectedFile().getAbsolutePath());
            }
        });
        top.setBorder(BorderFactory.createTitledBorder("Input File"));
        top.add(browseFileBtn, BorderLayout.WEST);
        top.add(selectedFileField, BorderLayout.CENTER);

        // ── Public Key panel ───────────────────────────────────────────
        fileOpPublicKeyArea = new JTextArea();
        try {
            fileOpPublicKeyArea.setText(Files.readString(Paths.get("publickey.pem")));
        } catch (IOException ignored) {}
        JPanel pubKeyPanel = new JPanel(new BorderLayout(4,4));
        pubKeyPanel.setBorder(BorderFactory.createTitledBorder("Public Key"));
        pubKeyPanel.add(new JScrollPane(fileOpPublicKeyArea), BorderLayout.CENTER);
        browseFileOpPublicBtn = new JButton("Browse Public…");
        browseFileOpPublicBtn.addActionListener(e -> onImportFileOpPublic());
        pubKeyPanel.add(browseFileOpPublicBtn, BorderLayout.SOUTH);

        // ── Private Key panel ──────────────────────────────────────────
        fileOpPrivateKeyArea = new JTextArea();
        try {
            fileOpPrivateKeyArea.setText(Files.readString(Paths.get("privatekey.pem")));
        } catch (IOException ignored) {}
        JPanel privKeyPanel = new JPanel(new BorderLayout(4,4));
        privKeyPanel.setBorder(BorderFactory.createTitledBorder("Private Key"));
        privKeyPanel.add(new JScrollPane(fileOpPrivateKeyArea), BorderLayout.CENTER);
        browseFileOpPrivateBtn = new JButton("Browse Private…");
        browseFileOpPrivateBtn.addActionListener(e -> onImportFileOpPrivate());
        privKeyPanel.add(browseFileOpPrivateBtn, BorderLayout.SOUTH);

        JSplitPane keysSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, pubKeyPanel, privKeyPanel);
        keysSplit.setResizeWeight(0.5);

        // ── Digital Signature display ─────────────────────────────────
        digitalSignatureField = new JTextField();
        digitalSignatureField.setBorder(BorderFactory.createTitledBorder("Digital Signature"));
        digitalSignatureField.setEditable(true);
        JScrollPane sigScroll = new JScrollPane(digitalSignatureField);

        JSplitPane centerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, keysSplit, sigScroll);
        centerSplit.setResizeWeight(0.7);

        // ── Action buttons ────────────────────────────────────────────
        JPanel btns = new JPanel();
        btns.add(new JButton("Encrypt File") {{ addActionListener(e -> encryptFileOpAsync()); }});
        btns.add(new JButton("Decrypt File") {{ addActionListener(e -> decryptFileOpAsync()); }});
        btns.add(new JButton("Generate Signature") {{ addActionListener(e -> generateSignature()); }});
        btns.add(new JButton("Verify Signature")   {{ addActionListener(e -> verifySignature()); }});

        panel.add(top,         BorderLayout.NORTH);
        panel.add(centerSplit, BorderLayout.CENTER);
        panel.add(btns,        BorderLayout.SOUTH);

        return panel;
    }

    

    private void generateSignature() {
        clearStatus();
        signFileOpAsync();
    }


    private void verifySignature() {
        clearStatus();
        verifyFileOpAsync();
    }

    private void onSelectFile() {
        JFileChooser fc = new JFileChooser(Paths.get("keys").toFile());
        if (fc.showOpenDialog(this)==JFileChooser.APPROVE_OPTION) {
            Path p = fc.getSelectedFile().toPath();
            selectedFileField.setText(p.toString());
            mostRecentField.setText("Selected: " + p.getFileName());
            signFileOpAsync();
        }
    }

    private void onImportFileOpPublic() {
        JFileChooser fc = new JFileChooser(Paths.get("keys").toFile());
        if (fc.showOpenDialog(this)==JFileChooser.APPROVE_OPTION) {
            try {
                fileOpPublicKeyArea.setText(
                        Files.readString(fc.getSelectedFile().toPath())
                );
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error importing public key: " + e.getMessage());
            }
        }
    }

    private void onImportFileOpPrivate() {
        JFileChooser fc = new JFileChooser(Paths.get("keys").toFile());
        if (fc.showOpenDialog(this)==JFileChooser.APPROVE_OPTION) {
            try {
                fileOpPrivateKeyArea.setText(
                        Files.readString(fc.getSelectedFile().toPath())
                );
                signFileOpAsync();
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error importing private key: " + e.getMessage());
            }
        }
    }
    private void signFileOpAsync() {
        final String filePath = selectedFileField.getText().trim();
        final String privText = fileOpPrivateKeyArea.getText().trim();
        if (filePath.isEmpty() || privText.isEmpty()) return;

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    byte[] data = Files.readAllBytes(Paths.get(filePath));
                    PrivateKey priv = parsePrivateKey(privText);
                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(priv);
                    sig.update(data);
                    return Base64.getEncoder().encodeToString(sig.sign());
                } catch (Exception e) {
                    return "ERROR: " + e.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    String result = get();
                    if (result.startsWith("ERROR: ")) {
                        statusBar.setForeground(Color.RED);
                        statusBar.setText(result.substring(7));
                        digitalSignatureField.setText("");
                    } else {
                        digitalSignatureField.setText(result);
                        mostRecentField.setForeground(Color.GREEN);
                        mostRecentField.setText("Signed " + Paths.get(filePath).getFileName());
                        statusBar.setText(" ");
                    }
                } catch (Exception e) {
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Signing error: " + e.getMessage());
                }
            }
        }.execute();
    }

    private void verifyFileOpAsync() {
        final String filePath = selectedFileField.getText().trim();
        final String sigB64   = digitalSignatureField.getText().trim();
        final String keyText  = fileOpPublicKeyArea.getText().trim();
        if (filePath.isEmpty() || sigB64.isEmpty()) return;

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                byte[] data     = Files.readAllBytes(Paths.get(filePath));
                byte[] sigBytes = Base64.getDecoder().decode(sigB64);

                for (String algo : SIGNATURE_ALGORITHMS) {
                    for (KeyWithName kw : parsePublicKeys(keyText)) {
                        try {
                            Signature v = Signature.getInstance(algo);
                            v.initVerify(kw.publicKey);
                            v.update(data);
                            if (v.verify(sigBytes)) {
                                return algo + " ✓ with " + kw.name;
                            }
                        } catch (Exception ignored) { }
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    String success = get();
                    if (success != null) {
                        mostRecentField.setForeground(Color.GREEN);
                        mostRecentField.setText(success);
                        statusBar.setForeground(Color.GREEN);
                        statusBar.setText("Verification successful");
                    } else {
                        mostRecentField.setForeground(Color.RED);
                        mostRecentField.setText("");
                        statusBar.setForeground(Color.RED);
                        statusBar.setText("Not verified with any key/algorithm");
                    }
                } catch (Exception e) {
                    mostRecentField.setForeground(Color.RED);
                    mostRecentField.setText("");
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Verification error: " + e.getMessage());
                }
            }
        }.execute();
    }

    // ─────────────────────────────────────────────────────────────────────────────
// Encrypt the selected file with the Public Key field (hybrid RSA/AES)
// ─────────────────────────────────────────────────────────────────────────────
    private void encryptFileOpAsync() {
        final String filePath = selectedFileField.getText().trim();
        final String pubText  = fileOpPublicKeyArea.getText().trim();
        if (filePath.isEmpty() || pubText.isEmpty()) return;

        new SwingWorker<Void,Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                PublicKey pub = parsePublicKey(pubText);
                encryptFileWithHybridRSA(filePath, pub);
                return null;
            }
            @Override
            protected void done() {
                try {
                    get();
                    mostRecentField.setForeground(Color.GREEN);
                    mostRecentField.setText("Encrypted " + Paths.get(filePath).getFileName());
                    statusBar.setText(" ");
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Encryption error: " + msg);
                }
            }
        }.execute();
    }

    // ─────────────────────────────────────────────────────────────────────────────
// Decrypt the selected file with the Private Key field (hybrid RSA/AES)
// ─────────────────────────────────────────────────────────────────────────────
    private void decryptFileOpAsync() {
        final String filePath = selectedFileField.getText().trim();
        final String privText = fileOpPrivateKeyArea.getText().trim();
        if (filePath.isEmpty() || privText.isEmpty()) return;

        new SwingWorker<Void,Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                PrivateKey priv = parsePrivateKey(privText);
                decryptFileWithHybridRSA(filePath, priv);
                return null;
            }
            @Override
            protected void done() {
                try {
                    get();
                    mostRecentField.setForeground(Color.GREEN);
                    mostRecentField.setText("Decrypted " + Paths.get(filePath).getFileName());
                    statusBar.setText(" ");
                } catch (Exception e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Decryption error: " + msg);
                }
            }
        }.execute();
    }
    
    public CryptoGui() {
        super("Crypto GUI");
        Security.addProvider(new BouncyCastleProvider());
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(800, 600);
        setLocationRelativeTo(null);

        initMenu();

        // Bottom panel with console message and status bar
        JPanel bottomPanel = new JPanel(new GridLayout(2, 1));
        mostRecentField = new JTextField();
        mostRecentField.setEditable(false);
        mostRecentField.setBorder(
                BorderFactory.createTitledBorder(
                        (TitledBorder) BorderFactory.createTitledBorder("Most Recent Console Message")
                ).getBorder()
        );
        statusBar = new JLabel(" ");
        bottomPanel.add(mostRecentField);
        bottomPanel.add(statusBar);
        add(bottomPanel, BorderLayout.SOUTH);

        initCards();
    }

    private void initMenu() {
        JMenuBar menuBar = new JMenuBar();
        String[] modes = { "Generate Keypair", "Sign", "Verify", "Encrypt", "Decrypt", "File Operations" };        for (String mode : modes) {
            JMenuItem item = new JMenuItem(mode);
            item.addActionListener(e -> showCard(mode));
            menuBar.add(item);
        }
        setJMenuBar(menuBar);
    }

    private void initCards() {
        cardLayout = new CardLayout();
        cardPanel = new JPanel(cardLayout);
        cardPanel.add(createGeneratePanel(), "Generate Keypair");
        cardPanel.add(createSignPanel(),     "Sign");
        cardPanel.add(createVerifyPanel(),   "Verify");
        cardPanel.add(createEncryptPanel(), "Encrypt");
        cardPanel.add(createDecryptPanel(), "Decrypt");
        cardPanel.add(createFileOperationsPanel(), "File Operations");
        add(cardPanel, BorderLayout.CENTER);
        showCard("Generate Keypair");
    }

    private void showCard(String name) {
        cardLayout.show(cardPanel, name);
        clearStatus();
        if ("Sign".equals(name)) {
            loadDefaultSignKey();
        }
        if ("Verify".equals(name)) loadDefaultVerifyKey();
        if ("Encrypt".equals(name)) loadDefaultEncryptKey();
        if ("Decrypt".equals(name)) loadDefaultDecryptKey();


        cardPanel.revalidate();
        cardPanel.repaint();
    }


    private JPanel createDecryptPanel() {
        JPanel panel = new JPanel(new BorderLayout(10,10));

        // ── PRIVATE KEY ─────────────────────────────────────────
        decryptPrivateKeyArea = new JTextArea();
        JScrollPane keyScroll = new JScrollPane(decryptPrivateKeyArea);
        keyScroll.setBorder(BorderFactory.createTitledBorder("PRIVATE KEY"));
        browseDecryptBtn = new JButton("Browse");
        browseDecryptBtn.addActionListener(e -> importDecryptKey());
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.add(keyScroll, BorderLayout.CENTER);
        keyPanel.add(browseDecryptBtn, BorderLayout.SOUTH);

        // ── ENCRYPTED TEXT INPUT ───────────────────────────────
        decryptInputArea = new JTextArea();
        JScrollPane inputScroll = new JScrollPane(decryptInputArea);
        inputScroll.setBorder(BorderFactory.createTitledBorder("Text to decrypt"));

        // ── DECRYPTED OUTPUT ───────────────────────────────────
        decryptOutputArea = new JTextArea();
        decryptOutputArea.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(decryptOutputArea);
        outputScroll.setBorder(BorderFactory.createTitledBorder("Decrypted text"));

        // Combine in split panes
        JSplitPane keyInputSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, keyPanel, inputScroll
        );
        keyInputSplit.setResizeWeight(0.3);

        JSplitPane mainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT, keyInputSplit, outputScroll
        );
        mainSplit.setResizeWeight(0.7);

        panel.add(mainSplit, BorderLayout.CENTER);

        // Trigger on any change
        DocumentListener dl = new SimpleDocListener(() -> {
            clearStatus();
            decryptAsync();
        });
        decryptPrivateKeyArea.getDocument().addDocumentListener(dl);
        decryptInputArea.getDocument().addDocumentListener(dl);

        return panel;
    }


    private void loadDefaultDecryptKey() {
        Path def = Paths.get("privatekey.pem");
        if (Files.exists(def)) {
            try {
                decryptPrivateKeyArea.setText(Files.readString(def));
                mostRecentField.setForeground(Color.GREEN);
                mostRecentField.setText("Loaded default private key");
            } catch (IOException e) {
                decryptPrivateKeyArea.setText("");
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error loading key: " + e.getMessage());
            }
        } else {
            decryptPrivateKeyArea.setText("");
            mostRecentField.setForeground(Color.RED);
            mostRecentField.setText("Default private key not found");
        }
        decryptAsync();
    }

    private void importDecryptKey() {
        JFileChooser fc = new JFileChooser(Paths.get("keys").toFile()); 
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                decryptPrivateKeyArea.setText(
                        Files.readString(fc.getSelectedFile().toPath())
                );
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error importing key: " + e.getMessage());
            }
        }
    }private void decryptAsync() {
        final String encB64  = decryptInputArea.getText().trim();
        final String privTxt = decryptPrivateKeyArea.getText().trim();

        new SwingWorker<String,Void>() {
            @Override
            protected String doInBackground() {
                try {
                    PrivateKey priv = parsePrivateKey(privTxt);
                    return decryptText(encB64, priv);
                } catch (BadPaddingException | IllegalBlockSizeException ex) {
                    return "ERROR: Invalid ciphertext or wrong key";
                } catch (Exception ex) {
                    return "ERROR: " + ex.getMessage();
                }
            }
            @Override
            protected void done() {
                try {
                    String res = get();
                    if (res.startsWith("ERROR: ")) {
                        String msg = res.substring(7);
                        decryptOutputArea.setText("");
                        statusBar.setForeground(Color.RED);
                        statusBar.setText(msg);
                    } else {
                        decryptOutputArea.setText(res);
                        mostRecentField.setForeground(Color.GREEN);
                        mostRecentField.setText("Decryption successful");
                        statusBar.setText(" ");
                    }
                } catch (InterruptedException|java.util.concurrent.ExecutionException e) {
                    String msg = e.getCause()!=null? e.getCause().getMessage() : e.getMessage();
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Decryption error: " + msg);
                }
            }
        }.execute();
    }


    private String decryptText(String encB64, PrivateKey privateKey) throws Exception {
        // 1) Normalize & pad Base64
        String clean = encB64.replaceAll("\\s+", "");
        int mod4 = clean.length() % 4;
        if (mod4 != 0) clean += "=".repeat(4 - mod4);

        byte[] in = Base64.getDecoder().decode(clean);

        // 2) Init RSA/PKCS1 cipher
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        // 3) Compute block size = ceil(bitLength/8)
        int modBits  = ((RSAPrivateCrtKey)privateKey).getModulus().bitLength();
        int keyBytes = (modBits + 7) / 8;

        // 4) Chunk-by-chunk decrypt
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (int off = 0; off < in.length; off += keyBytes) {
            int len = Math.min(keyBytes, in.length - off);
            try {
                out.write(cipher.doFinal(in, off, len));
            } catch (BadPaddingException|IllegalBlockSizeException e) {
                throw new BadPaddingException(
                        "Decryption failed at block " + (off/keyBytes) + ": " + e.getMessage()
                );
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }


    private JPanel createEncryptPanel() {
        JPanel panel = new JPanel(new BorderLayout(10,10));

        // ── PRIVATE KEY ───────────────────────────────────────────────
        encryptPublicKeyArea = new JTextArea();
        JScrollPane keyScroll = new JScrollPane(encryptPublicKeyArea);
        keyScroll.setBorder(BorderFactory.createTitledBorder("PUBLIC KEY"));
        browseEncryptBtn = new JButton("Browse");
        browseEncryptBtn.addActionListener(e -> importEncryptKey());
        JPanel keyPanel = new JPanel(new BorderLayout());
        keyPanel.add(keyScroll, BorderLayout.CENTER);
        keyPanel.add(browseEncryptBtn, BorderLayout.SOUTH);

        // ── PLAINTEXT INPUT ───────────────────────────────────────────
        encryptInputArea = new JTextArea();
        JScrollPane inputScroll = new JScrollPane(encryptInputArea);
        inputScroll.setBorder(BorderFactory.createTitledBorder("Plaintext"));

        // Build top split (key vs. plaintext)
        JSplitPane keyInputSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                keyPanel,
                inputScroll
        );
        keyInputSplit.setResizeWeight(0.3);

        // ── CIPHERTEXT OUTPUT ────────────────────────────────────────
        encryptOutputArea = new JTextArea();
        encryptOutputArea.setEditable(false);
        JScrollPane outputScroll = new JScrollPane(encryptOutputArea);
        outputScroll.setBorder(BorderFactory.createTitledBorder("Encrypted (Base64)"));

        // ── MAIN SPLIT (above vs. ciphertext) ─────────────────────────
        JSplitPane mainSplit = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                keyInputSplit,
                outputScroll
        );
        mainSplit.setResizeWeight(0.7);
        panel.add(mainSplit, BorderLayout.CENTER);

        // ── trigger on any change ────────────────────────────────────
        DocumentListener dl = new SimpleDocListener(() -> {
            clearStatus();
            encryptAsync();
        });
        encryptPublicKeyArea.getDocument().addDocumentListener(dl);
        encryptInputArea.getDocument().addDocumentListener(dl);

        return panel;
    }


    private void loadDefaultEncryptKey() {
        Path def = Paths.get("publickey.pem");
        if (Files.exists(def)) {
            try {
                encryptPublicKeyArea.setText(Files.readString(def));
                mostRecentField.setForeground(Color.GREEN);
                mostRecentField.setText("Loaded default public key");
            } catch (IOException e) {
                encryptPublicKeyArea.setText("");
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error loading default key: " + e.getMessage());
            }
        } else {
            encryptPublicKeyArea.setText("");
            mostRecentField.setForeground(Color.RED);
            mostRecentField.setText("Default public key not found");
        }
        encryptAsync();
    }


    private void importEncryptKey() {
        JFileChooser fc = new JFileChooser(Paths.get("keys").toFile());
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                encryptPublicKeyArea.setText(
                        Files.readString(fc.getSelectedFile().toPath())
                );
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error importing public key: " + e.getMessage());
            }
        }
    }   

    private void encryptAsync() {
        final String text     = encryptInputArea.getText();

        new SwingWorker<String,Void>() {
            @Override
            protected String doInBackground() {
                try {
                    PublicKey pub = parsePublicKey(encryptPublicKeyArea.getText().trim());
                    return encryptText(text, pub);
                } catch (Exception ex) {
                    return "ERROR: " + ex.getMessage();
                }
            }
            @Override
            protected void done() {
                try {
                    String res = get();
                    if (res.startsWith("ERROR: ")) {
                        String msg = res.substring(7);
                        statusBar.setForeground(Color.RED);
                        statusBar.setText(msg);
                        encryptOutputArea.setText("");
                    } else {
                        encryptOutputArea.setText(res);
                        mostRecentField.setForeground(Color.GREEN);
                        mostRecentField.setText("Encryption successful");
                        statusBar.setText(" ");
                    }
                } catch (InterruptedException|java.util.concurrent.ExecutionException e) {
                    String msg = e.getCause()!=null
                            ? e.getCause().getMessage()
                            : e.getMessage();
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Encryption error: " + msg);
                }
            }
        }.execute();
    }

    private String encryptText(String text, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] in = text.getBytes(StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int bs = 245, offset = 0;
        while (offset < in.length) {
            int len = Math.min(bs, in.length - offset);
            out.write(cipher.doFinal(in, offset, len));
            offset += len;
        }
        return Base64.getEncoder().encodeToString(out.toByteArray());
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Generate Keypair Tab
    // ─────────────────────────────────────────────────────────────────────────────

    private JPanel createGeneratePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // Key text areas with titled borders
        privateKeyArea = new JTextArea();
        publicKeyArea  = new JTextArea();

        JPanel privPanel = new JPanel(new BorderLayout());
        privPanel.setBorder(BorderFactory.createTitledBorder("PRIVATE KEY"));
        privPanel.add(new JScrollPane(privateKeyArea), BorderLayout.CENTER);

        JPanel pubPanel = new JPanel(new BorderLayout());
        pubPanel.setBorder(BorderFactory.createTitledBorder("PUBLIC KEY"));
        pubPanel.add(new JScrollPane(publicKeyArea), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                privPanel,
                pubPanel
        );
        split.setResizeWeight(0.5);
        panel.add(split, BorderLayout.CENTER);

        // Controls
        JPanel controlPanel = new JPanel();
        JButton generateBtn = new JButton("Generate");
        JButton importBtn   = new JButton("Import Private Key");
        JButton saveBtn     = new JButton("Save As");
        pemRadio    = new JRadioButton("PEM");
        base64Radio = new JRadioButton("Base64");
        ButtonGroup fmtGroup = new ButtonGroup();
        fmtGroup.add(pemRadio);
        fmtGroup.add(base64Radio);
        pemRadio.setSelected(true);

        controlPanel.add(generateBtn);
        controlPanel.add(importBtn);
        controlPanel.add(saveBtn);
        controlPanel.add(pemRadio);
        controlPanel.add(base64Radio);
        panel.add(controlPanel, BorderLayout.NORTH);

        // Listeners
        generateBtn.addActionListener(e -> onGenerate());
        importBtn.addActionListener(e -> onImport());
        saveBtn.addActionListener(e -> onSaveAs());
        privateKeyArea.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { clearStatus(); }
            public void removeUpdate(DocumentEvent e) { clearStatus(); }
            public void changedUpdate(DocumentEvent e) { clearStatus(); }
        });
        pemRadio.addActionListener(e -> clearStatus());
        base64Radio.addActionListener(e -> clearStatus());

        return panel;
    }

    private void onGenerate() {
        try {
            clearStatus();
            KeyPair pair;
            String privText = privateKeyArea.getText().trim();
            if (!privText.isEmpty()) {
                try {
                    PrivateKey priv = parsePrivateKey(privText);
                    PublicKey pub  = derivePublicKey(priv);
                    pair = new KeyPair(pub, priv);
                    mostRecentField.setForeground(Color.GREEN);
                    mostRecentField.setText("Derived from private");
                } catch (Exception ex) {
                    pair = generateNewKeyPair();
                    mostRecentField.setForeground(Color.GREEN);
                    mostRecentField.setText("Successful generate from scratch");
                    showError("Invalid private key, generating new keypair.");
                }
            } else {
                pair = generateNewKeyPair();
                mostRecentField.setForeground(Color.GREEN);
                mostRecentField.setText("Successful generate from scratch");
            }
            privateKeyArea.setText(formatKey(pair.getPrivate()));
            publicKeyArea.setText(formatKey(pair.getPublic()));
        } catch (Exception ex) {
            showError("Error generating keypair: " + ex.getMessage());
            mostRecentField.setForeground(Color.RED);
            mostRecentField.setText(ex.getMessage());
        }
    }

    private KeyPair generateNewKeyPair() throws Exception {
        SecureRandom rnd = SecureRandom.getInstanceStrong();
        rnd.setSeed(System.currentTimeMillis() ^ new Random().nextLong());
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048, rnd);
        return gen.generateKeyPair();
    }

    private PrivateKey parsePrivateKey(String text) throws Exception {
        String b64 = text
                .replaceAll("-----.*-----", "")
                .replaceAll("\\s", "");
        byte[] keyBytes = Base64.getDecoder().decode(b64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    private PublicKey derivePublicKey(PrivateKey priv) throws Exception {
        if (priv instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey crt = (RSAPrivateCrtKey) priv;
            RSAPublicKeySpec spec = new RSAPublicKeySpec(
                    crt.getModulus(),
                    crt.getPublicExponent()
            );
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
        throw new InvalidKeyException(
                "Cannot derive public key from provided private key type."
        );
    }

    private String formatKey(Key key) {
        byte[] enc = key.getEncoded();
        String b64 = Base64.getEncoder().encodeToString(enc);
        if (pemRadio.isSelected()) {
            String type = (key instanceof PrivateKey) ? "PRIVATE" : "PUBLIC";
            String header = "-----BEGIN " + type + " KEY-----\n";
            String footer = "-----END " + type + " KEY-----";
            return header + wrapPem(b64) + footer;
        } else {
            return b64;
        }
    }

    private String wrapPem(String b64) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length()))
                    .append("\n");
        }
        return sb.toString();
    }

    private void onImport() {
        try {
            clearStatus();
            JFileChooser chooser = new JFileChooser(Paths.get("keys").toFile());
            if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                Path p = chooser.getSelectedFile().toPath();
                privateKeyArea.setText(Files.readString(p));
            }
        } catch (IOException ex) {
            showError("Error importing key: " + ex.getMessage());
        }
    }

    private void onSaveAs() {
        try {
            clearStatus();
            String name = JOptionPane.showInputDialog(
                    this,
                    "Enter base name for key files:"
            );
            if (name == null || name.isBlank()) return;

            Path dir = Paths.get("keys");
            if (!Files.exists(dir)) Files.createDirectories(dir);

            String ext = pemRadio.isSelected() ? ".pem" : ".b64";
            Path privFile = dir.resolve(name + "_private" + ext);
            Path pubFile  = dir.resolve(name + "_public"  + ext);

            if (Files.exists(privFile) || Files.exists(pubFile)) {
                showError("File(s) exist, choose a different name.");
                return;
            }

            Files.writeString(privFile, privateKeyArea.getText());
            Files.writeString(pubFile,  publicKeyArea.getText());

            statusBar.setForeground(Color.BLACK);
            statusBar.setText(
                    "Saved to: " + privFile + ", " + pubFile
            );
        } catch (Exception ex) {
            showError("Error saving keys: " + ex.getMessage());
        }
    }

    private void onFormatChanged() {
        clearStatus();
    }

    private void showError(String msg) {
        statusBar.setForeground(Color.RED);
        statusBar.setText(msg);
    }

    private void clearStatus() {
        statusBar.setForeground(Color.BLACK);
        statusBar.setText(" ");
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // Sign Tab
    // ─────────────────────────────────────────────────────────────────────────────
    private JPanel createSignPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));

        // ── PRIVATE KEY ─────────────────────────────────────────────
        signPrivateKeyArea = new JTextArea();
        JPanel privPanel = new JPanel(new BorderLayout());
        privPanel.setBorder(BorderFactory.createTitledBorder("PRIVATE KEY"));
        privPanel.add(new JScrollPane(signPrivateKeyArea), BorderLayout.CENTER);

        browseSignBtn = new JButton("Browse");
        browseSignBtn.addActionListener(e -> importSignKey());
        privPanel.add(browseSignBtn, BorderLayout.SOUTH);

        // ── STUFF TO SIGN ───────────────────────────────────────────
        stuffToSignArea = new JTextArea();
        JPanel stuffPanel = new JPanel(new BorderLayout());
        stuffPanel.setBorder(BorderFactory.createTitledBorder("Stuff to sign"));
        stuffPanel.add(new JScrollPane(stuffToSignArea), BorderLayout.CENTER);

        JSplitPane split = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                privPanel,
                stuffPanel
        );
        split.setResizeWeight(0.4);
        panel.add(split, BorderLayout.CENTER);

        // ── ADD TIMESTAMP ───────────────────────────────────────────
        JPanel btnPanel = new JPanel();
        addTimestampBtn = new JButton("Add Timestamp");
        addTimestampBtn.addActionListener(e -> appendTimestamp());
        btnPanel.add(addTimestampBtn);
        panel.add(btnPanel, BorderLayout.NORTH);

        // ── AUTOMATIC SIGNING ON CHANGE ────────────────────────────
        SimpleDocListener autoSigner = new SimpleDocListener(() -> {
            clearStatus();
            signNow();
        });
        signPrivateKeyArea.getDocument().addDocumentListener(autoSigner);
        stuffToSignArea  .getDocument().addDocumentListener(autoSigner);

        return panel;
    }

    private void loadDefaultSignKey() {
        Path def = Paths.get("privatekey.pem");
        if (Files.exists(def)) {
            try {
                signPrivateKeyArea.setText(Files.readString(def));
                mostRecentField.setForeground(Color.GREEN);
                mostRecentField.setText("Loaded default private key");
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error loading default key: " + e.getMessage());
            }
        } else {
            signPrivateKeyArea.setText("");
            // do NOT clear stuffToSignField here
            mostRecentField.setForeground(Color.RED);
            mostRecentField.setText(
                    "Default private key not found at " + def
            );
        }
    }

    private void importSignKey() {
        JFileChooser chooser = new JFileChooser(Paths.get("keys").toFile());
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            try {
                String txt = Files.readString(
                        chooser.getSelectedFile().toPath()
                );
                signPrivateKeyArea.setText(txt);
            } catch (IOException e) {
                mostRecentField.setForeground(Color.RED);
                mostRecentField.setText("Error importing key: " + e.getMessage());
            }
        }
    }

    private void appendTimestamp() {
        stuffToSignArea.setText(
                stuffToSignArea.getText() + " | Signed at " + System.currentTimeMillis()
        );
    }

    private void signNow() {
        try {
            clearStatus();
            PrivateKey priv = parsePrivateKey(
                    signPrivateKeyArea.getText().trim()
            );
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(priv);
            byte[] data = stuffToSignArea
                    .getText()
                    .getBytes(StandardCharsets.UTF_8);
            signer.update(data);
            byte[] sigBytes = signer.sign();
            String sigB64 = Base64.getEncoder().encodeToString(sigBytes);

            mostRecentField.setForeground(Color.GREEN);
            mostRecentField.setText("Signature: " + sigB64);
        } catch (Exception ex) {
            showError("Sign error: " + ex.getMessage());
            mostRecentField.setForeground(Color.RED);
            mostRecentField.setText(ex.getMessage());
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new CryptoGui().setVisible(true);
        });
    }

    private JPanel createVerifyPanel() {
        JPanel p = new JPanel(new BorderLayout(10,10));

        // Text to verify
        textToVerifyArea = new JTextArea();
        JPanel textP = new JPanel(new BorderLayout());
        textP.setBorder(BorderFactory.createTitledBorder("Text to verify"));
        textP.add(new JScrollPane(textToVerifyArea), BorderLayout.CENTER);

        // Public key(s)
        verifyPublicKeyArea = new JTextArea();
        JPanel keyP = new JPanel(new BorderLayout());
        keyP.setBorder(BorderFactory.createTitledBorder("PUBLIC KEY(S)"));
        keyP.add(new JScrollPane(verifyPublicKeyArea), BorderLayout.CENTER);
        JButton impPubBtn = new JButton("Import Public Key(s)");
        impPubBtn.addActionListener(e -> importVerifyKey());
        keyP.add(impPubBtn, BorderLayout.SOUTH);

        // Signature field
        signatureField = new JTextField();
        JPanel sigP = new JPanel(new BorderLayout());
        sigP.setBorder(BorderFactory.createTitledBorder("Signature (Base64)"));
        sigP.add(signatureField, BorderLayout.CENTER);

        // Stack them
        JPanel center = new JPanel(new GridLayout(3,1,5,5));
        center.add(textP);
        center.add(keyP);
        center.add(sigP);
        p.add(center, BorderLayout.CENTER);

        // Attach two listeners to each field:
        // 1) clearStatus() on any change
        // 2) verifyAsync() on any change
        DocumentListener clearAndVerify = new SimpleDocListener(() -> {
            clearStatus();
            verifyAsync();
        });
        textToVerifyArea.getDocument().addDocumentListener(clearAndVerify);
        verifyPublicKeyArea.getDocument().addDocumentListener(clearAndVerify);
        signatureField.getDocument().addDocumentListener(clearAndVerify);

        return p;
    }

          private void loadDefaultVerifyKey() {
              Path def = Paths.get("publickey.pem");
              if (Files.exists(def)) {
                      try {
                                      String content = Files.readString(def);
                                      verifyPublicKeyArea.setText(content);
                                      mostRecentField.setForeground(Color.GREEN);
                                      mostRecentField.setText("Loaded default public key");
                                  } catch (IOException e) {
                                      verifyPublicKeyArea.setText("");
                                      mostRecentField.setForeground(Color.RED);
                                      mostRecentField.setText("Error loading default public key: " + e.getMessage());
                                  }
                          } else {
                              verifyPublicKeyArea.setText("");
                              mostRecentField.setForeground(Color.RED);
                              mostRecentField.setText("Default public key not found");
                          }
              verifyAsync();
          }

          private void importVerifyKey() {
              JFileChooser fc = new JFileChooser(Paths.get("keys").toFile());             
              if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
                  try {
                      String content = Files.readString(fc.getSelectedFile().toPath());
                      verifyPublicKeyArea.setText(content);
                  } catch (IOException e) {
                      mostRecentField.setForeground(Color.RED);
                      mostRecentField.setText("Error importing public key: " + e.getMessage());
                  }
              }
          }
    private void verifyAsync() {
        final String text    = textToVerifyArea.getText();
        final String sigB64  = signatureField.getText().trim();
        final String keyText = verifyPublicKeyArea.getText();
        if (sigB64.isEmpty() || keyText.trim().isEmpty()) return;

        new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() {
                try {
                    byte[] sigBytes = Base64.getDecoder().decode(sigB64);
                    byte[] data     = text.getBytes(StandardCharsets.UTF_8);

                    for (String algo : SIGNATURE_ALGORITHMS) {
                        for (KeyWithName kw : parsePublicKeys(keyText)) {
                            try {
                                Signature v = Signature.getInstance(algo);
                                v.initVerify(kw.publicKey);
                                v.update(data);
                                if (v.verify(sigBytes)) {
                                    return algo + " ✓ verified with " + kw.name;
                                }
                            } catch (Exception ignored) { }
                        }
                    }
                    return "NOT VERIFIED";
                } catch (Exception ex) {
                    return "ERROR: " + ex.getMessage();
                }
            }

            @Override
            protected void done() {
                try {
                    String res = get();
                    if (res.startsWith("ERROR: ")) {
                        String msg = res.substring(7);
                        statusBar.setForeground(Color.RED);
                        statusBar.setText(msg);
                    } else if (res.equals("NOT VERIFIED")) {
                        statusBar.setForeground(Color.RED);
                        statusBar.setText("Not verified with any key/algorithm");
                    } else {
                        // res already contains algo and key name
                        mostRecentField.setForeground(Color.GREEN);
                        mostRecentField.setText(res);
                        statusBar.setForeground(Color.GREEN);
                        statusBar.setText("Verification successful");
                    }
                } catch (InterruptedException | java.util.concurrent.ExecutionException e) {
                    String msg = e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
                    statusBar.setForeground(Color.RED);
                    statusBar.setText("Verification error: " + msg);
                }
            }
        }.execute();
    }

          // parse either a single PEM/Base64 key or a JSON envelope {"keys":[{name,public},…]}
          private List<KeyWithName> parsePublicKeys(String keyText) throws Exception {
              List<KeyWithName> result = new ArrayList<>();

              // Parse keys from the text area (single key or JSON envelope)
              keyText = keyText.trim();
              if (keyText.startsWith("{")) {
                  JSONObject obj = new JSONObject(keyText);
                  JSONArray arr = obj.getJSONArray("keys");
                  for (int i = 0; i < arr.length(); i++) {
                      JSONObject e = arr.getJSONObject(i);
                      String name = e.optString("name", "key" + i);
                      String pub  = e.getString("public");
                      result.add(new KeyWithName(name, parsePublicKey(pub)));
                  }
              } else if (!keyText.isEmpty()) {
                  result.add(new KeyWithName("publickey.pem", parsePublicKey(keyText)));
              }

              // Also load all public key files under /keys (*.pem or *.b64)
              Path keyDir = Paths.get("keys");
              if (Files.isDirectory(keyDir)) {
                  try (DirectoryStream<Path> ds = Files.newDirectoryStream(keyDir, "*.{pem,b64}")) {
                      for (Path p : ds) {
                          try {
                              String content = Files.readString(p);
                              PublicKey pk = parsePublicKey(content);
                              result.add(new KeyWithName(p.getFileName().toString(), pk));
                          } catch (Exception ignored) {
                              // skip files that can't be parsed
                          }
                      }
                  }
              }

              return result;
          }

    /** Strips PEM headers (if present), Base64-decodes, and builds an RSA PublicKey. */
    private PublicKey parsePublicKey(String text) throws Exception {
        String b64 = text
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s+", "");
        byte[] data = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

          private static class KeyWithName {
      final String   name;
      final PublicKey publicKey;
      KeyWithName(String n, PublicKey pk) { name = n; publicKey = pk; }
  }


    private static class SimpleDocListener implements DocumentListener {
        private final Runnable r;
        public SimpleDocListener(Runnable r) { this.r = r; }
        @Override public void insertUpdate(DocumentEvent e) { r.run(); }
        @Override public void removeUpdate(DocumentEvent e) { r.run(); }
        @Override public void changedUpdate(DocumentEvent e) { r.run(); }
    }
}
