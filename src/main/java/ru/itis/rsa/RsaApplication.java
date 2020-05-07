package ru.itis.rsa;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class RsaApplication {

    public static void main(String[] args) throws Exception {
        SpringApplication.run(RsaApplication.class, args);
        GenerateKeys generator = new GenerateKeys(1024);
        generator.generate();
        AsymmetricCryptography cryptography = new AsymmetricCryptography();

        GostAlgorithm gostAlgorithm = new GostAlgorithm(cryptography.getPublic("src\\main\\resources\\public.key").toString());
        cryptography.getText(gostAlgorithm);

    }
}
