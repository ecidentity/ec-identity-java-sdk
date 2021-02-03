package io.ecidentity.integration.utils;

import com.google.protobuf.AbstractMessage;
import com.google.protobuf.ByteString;
import com.google.protobuf.Descriptors;
import io.ecidentity.protocol.types.ResultCodeExtProtocol;

import java.util.Map;

public class MessageUtils {

    private static final String PAYLOAD = "payload";
    private static final String SIGNATURE = "signature";
    private static final String RESULT_CODE = "result_code";

    public static AbstractMessage getPayload(AbstractMessage message) {
        return (AbstractMessage) getFieldValue(message, PAYLOAD);
    }

    public static ResultCodeExtProtocol getResultCode(AbstractMessage message) {
        if (getFieldValue(message, RESULT_CODE) != null)
            return ResultCodeExtProtocol.valueOf((Descriptors.EnumValueDescriptor) getFieldValue(message, RESULT_CODE));
        else return ResultCodeExtProtocol.OK;
    }

    public static ByteString getSignature(AbstractMessage message) {
        return (ByteString) getFieldValue(message, SIGNATURE);
    }

    private static Object getFieldValue(AbstractMessage message, String fieldName) {
        return message.getAllFields()
                .entrySet()
                .stream()
                .filter(entry -> entry.getKey().getName().equals(fieldName))
                .findFirst()
                .map(Map.Entry::getValue).orElse(null);
    }
}
