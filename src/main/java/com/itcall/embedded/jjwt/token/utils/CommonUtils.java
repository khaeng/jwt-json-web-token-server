package com.itcall.embedded.jjwt.token.utils;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
//import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
//import com.fasterxml.jackson.annotation.JsonIdentityInfo;
//import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
//import com.fasterxml.jackson.annotation.JsonProperty;
//import com.fasterxml.jackson.annotation.JsonTypeInfo;
//import com.fasterxml.jackson.annotation.ObjectIdGenerators;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.json.JsonReadFeature;
//import com.fasterxml.jackson.databind.BeanDescription;
//import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
//import com.fasterxml.jackson.databind.JavaType;
//import com.fasterxml.jackson.databind.JsonDeserializer;
//import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
//import com.fasterxml.jackson.databind.cfg.DeserializerFactoryConfig;
//import com.fasterxml.jackson.databind.deser.BeanDeserializerFactory;
//import com.fasterxml.jackson.databind.deser.DefaultDeserializationContext;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

public class CommonUtils {

	public static final ObjectMapper MAPPER /* = new ObjectMapper() */;

	static {
		MAPPER = JsonMapper.builder()
				.visibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY)
				.configure(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS, true)
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false) // 직열화 시: 
				.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false) // 역직열화 시: POJO에 Field가 존재하지 않는 JSON key에 대해서 실패(에러)처리 여부.
				.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, false) // Field에 null 값인 경우 실패(에러)처리 여부. false이면 null 허용. 기본값 여부.
				.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, false) // 열거형 Field에 대해 숫자에 대한 변환을 할것인지 여부. 문자열로만 처리할 경우 . true로 셋팅한다.
				.addModule(new JavaTimeModule())
				.build();
//		MAPPER.configure(JsonReadFeature.ALLOW_NON_NUMERIC_NUMBERS, true);
//		MAPPER.registerModule(new Hibernate5Module());
		
		/*******************************************
		try {
			String json = MAPPER.writer()
					.with(SerializationFeature.INDENT_OUTPUT)
					.without(SerializationFeature.FAIL_ON_EMPTY_BEANS)
					.writeValueAsString(new Object());
		} catch (JsonProcessingException e) {
			e.printStackTrace();
		}
		 *******************************************/
	}


}
