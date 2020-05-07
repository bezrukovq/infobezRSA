package ru.itis.rsa;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public class GostAlgorithm {

    private String key;
    private String text;

    private byte[] k;

    private final byte[][] Sbox = new byte[][]{
            {0x04, 0x0a, 0x09, 0x02, 0x0d, 0x08, 0x00, 0x0e, 0x06, 0x0B, 0x01, 0x0c, 0x07, 0x0f, 0x05, 0x03},
            {0x0e, 0x0b, 0x04, 0x0c, 0x06, 0x0d, 0x0f, 0x0a, 0x02, 0x03, 0x08, 0x01, 0x00, 0x07, 0x05, 0x09},
            {0x05, 0x08, 0x01, 0x0d, 0x0a, 0x03, 0x04, 0x02, 0x0e, 0x0f, 0x0c, 0x07, 0x06, 0x00, 0x09, 0x0b},
            {0x07, 0x0d, 0x0a, 0x01, 0x00, 0x08, 0x09, 0x0f, 0x0e, 0x04, 0x06, 0x0c, 0x0b, 0x02, 0x05, 0x03},
            {0x06, 0x0c, 0x07, 0x01, 0x05, 0x0f, 0x0d, 0x08, 0x04, 0x0a, 0x09, 0x0e, 0x00, 0x03, 0x0b, 0x02},
            {0x04, 0x0b, 0x0a, 0x00, 0x07, 0x02, 0x01, 0x0d, 0x03, 0x06, 0x08, 0x05, 0x09, 0x0c, 0x0f, 0x0e},
            {0x0d, 0x0b, 0x04, 0x01, 0x03, 0x0f, 0x05, 0x09, 0x00, 0x0a, 0x0e, 0x07, 0x06, 0x08, 0x02, 0x0c},
            {0x01, 0x0f, 0x0d, 0x00, 0x05, 0x07, 0x0a, 0x04, 0x09, 0x02, 0x03, 0x0e, 0x06, 0x0b, 0x08, 0x0c}
    };

    public GostAlgorithm(String key) {
        if (key.length() <= 31) {
            throw new IllegalArgumentException("Key must contain 32+ symbols!");
        }

        this.key = key;
        this.k = this.key.getBytes(Charset.forName("UTF-8"));
    }

    public void doAlgorithm(String text) {
        byte[] encoded = Gost28147_89EncodeBasic(text, k);
        PrintByteArray(encoded);

        byte[] decoded = Gost28147_89DecodeBasic(encoded, k);

        System.out.println("Result of decrypt\n" + new String(decoded, StandardCharsets.UTF_8) + "\n");
    }

    public byte[] Gost28147_89EncodeBasic(String text, byte[] k) {
        byte[] TextByteArray = PrepareByteArray(text);
        byte[] result = new byte[TextByteArray.length];

        int offset = 0;

        while (offset < TextByteArray.length) {
            byte[] encrypted = Gost28147_89EncodeBlockFunction(Get64BitBlockFromArray(TextByteArray, offset), this.k);
            System.arraycopy(encrypted, 0, result, offset, encrypted.length);
            offset += 8;
        }
        return result;
    }

    public byte[] Gost28147_89DecodeBasic(byte[] array, byte[] k) {
        byte[] TextByteArray = array;
        byte[] result = new byte[TextByteArray.length];

        int offset = 0;

        while (offset < TextByteArray.length) {
            byte[] encrypted = Gost28147_89DecodeBlockFunction(Get64BitBlockFromArray(TextByteArray, offset), this.k);
            System.arraycopy(encrypted, 0, result, offset, encrypted.length);
            offset += 8;
        }

        return result;
    }

    private byte[] Gost28147_89EncodeBlockFunction(byte[] block, byte[] k) {
        int N1 = BytesToint(Get32BitBlockFromArray(block, 0), 0);//first 32 bits
        int N2 = BytesToint(Get32BitBlockFromArray(block, 4), 0);//last  32 bits

        for (int i = 0; i < 3; i++) {
            for (int ki = 0; ki < 8; ki++) {
                int temp = N1;
                N1 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, ki * 4), 0));
                N2 = temp;
            }
        }

        for (int ki = 7; ki > 0; ki--)  // 25-31 steps
        {
            int tmp = N1;
            N1 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, ki * 4), 0)); // CM2
            N2 = tmp;
        }

        N2 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, 0), 0));  // 32 step (N1=N1)

        byte[] result = new byte[8];
        IntTobytes(N1, result, 0);
        IntTobytes(N2, result, 4);

        return result;

    }

    private byte[] Gost28147_89DecodeBlockFunction(byte[] block, byte[] k) {
        int N1 = BytesToint(Get32BitBlockFromArray(block, 0), 0);//first 32 bits
        int N2 = BytesToint(Get32BitBlockFromArray(block, 4), 0);//last  32 bits

        for (int ki = 0; ki < 8; ki++)  // 1-8 steps
        {
            int tmp = N1;
            N1 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, ki * 4), 0)); // CM2
            N2 = tmp;
        }
        for (int i = 0; i < 3; i++)  //9-31 steps
        {
            for (int ki = 7; ki >= 0; ki--) {
                if ((i == 2) && (ki == 0)) {
                    break; // break 32 step
                }
                int tmp = N1;
                N1 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, ki * 4), 0)); // CM2
                N2 = tmp;
            }
        }

        N2 = N2 ^ Gost28147_89MainStep(N1, BytesToint(Get32BitBlockFromArray(k, 0), 0));  // 32 step (N1=N1)

        byte[] result = new byte[8];
        IntTobytes(N1, result, 0);
        IntTobytes(N2, result, 4);

        return result;
    }

    private int Gost28147_89MainStep(int n1, int key) {
        int cm = (key + n1); // CM1

        // S-box replacing
        int om = Sbox[0][((cm >> (0 * 4)) & 0xF)] << (0 * 4);
        om += Sbox[1][((cm >> (1 * 4)) & 0xF)] << (1 * 4);
        om += Sbox[2][((cm >> (2 * 4)) & 0xF)] << (2 * 4);
        om += Sbox[3][((cm >> (3 * 4)) & 0xF)] << (3 * 4);
        om += Sbox[4][((cm >> (4 * 4)) & 0xF)] << (4 * 4);
        om += Sbox[5][((cm >> (5 * 4)) & 0xF)] << (5 * 4);
        om += Sbox[6][((cm >> (6 * 4)) & 0xF)] << (6 * 4);
        om += Sbox[7][((cm >> (7 * 4)) & 0xF)] << (7 * 4);
        return om << 11 | om >>> (32 - 11); // 11 bit-leftshift
    }


    private byte[] PrepareByteArray(String text) {
        byte[] original = text.getBytes(Charset.forName("UTF-8"));
        int blocksCount = original.length % 8;

        if (blocksCount != 0) {
            blocksCount = original.length / 8 + 1;
        } else {
            blocksCount = original.length / 8;
        }

        byte[] result = new byte[blocksCount * 8];
        System.arraycopy(text.getBytes(Charset.forName("UTF-8")), 0, result, 0, original.length);

        return result;
    }

    private byte[] Get64BitBlockFromArray(byte[] array, int offset) {
        byte[] result = new byte[8];
        System.arraycopy(array, offset, result, 0, 8);
        return result;
    }

    private byte[] Get32BitBlockFromArray(byte[] array, int offset) {
        byte[] result = new byte[4];
        System.arraycopy(array, offset, result, 0, 4);
        return result;
    }

    //array of bytes to type int
    private int BytesToint(byte[] in, int inOff) {
        return ((in[inOff + 3] << 24) & 0xff000000) + ((in[inOff + 2] << 16) & 0xff0000) +
                ((in[inOff + 1] << 8) & 0xff00) + (in[inOff] & 0xff);
    }

    //int to array of bytes
    private void IntTobytes(int num, byte[] out, int outOff) {
        out[outOff + 3] = (byte) (num >>> 24);
        out[outOff + 2] = (byte) (num >>> 16);
        out[outOff + 1] = (byte) (num >>> 8);
        out[outOff] = (byte) num;
    }

    private void PrintByteArray(byte[] array) {
        String result = "";
        for (byte b : array) {
            byte[] temp = new byte[1];
            temp[0] = b;
            result += Byte.toString(b) + " ";
        }

        System.out.println("Result of crypt\n" + result + "\n");
    }
}