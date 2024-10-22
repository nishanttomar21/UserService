// Kafka Producer - User Service
// Kafka Consumer - Email Service
// @Component - Indicates that this class is a Spring bean and should be managed by Spring. This is the base class for all Spring-managed beans.
// KafkaTemplate - A Spring Kafka client for sending and receiving messages to Kafka topics (Sister of RestTemplate).
// Flow: SignUp (Producer) --> Email Service (Consumer) --> Send welcome email for new SignUp
// How to install kafka on Mac - https://learn.conduktor.io/kafka/how-to-install-apache-kafka-on-mac/
// Logic for sending emails - https://www.digitalocean.com/community/tutorials/javamail-example-send-mail-in-java-smtp

package org.example.userservice.client;

import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Component;

@Component
public class KafkaProducerClient {

    private KafkaTemplate<String,String> kafkaTemplate;     // <Topic, Message>

    public KafkaProducerClient(KafkaTemplate<String,String> kafkaTemplate) {
        this.kafkaTemplate = kafkaTemplate;
    }

    public void sendMessage(String topic,String message) {
        kafkaTemplate.send(topic,message);
    }
}
