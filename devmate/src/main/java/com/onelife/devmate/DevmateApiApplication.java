package com.onelife.devmate;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing
public class DevmateApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(DevmateApiApplication.class, args);
	}

}
