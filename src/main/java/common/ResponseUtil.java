package common;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by Sarm_Brights on 1/13/2017.
 */
public class ResponseUtil {

    private static Boolean status;

    private static Integer intData;
    private static byte[] bytesData;
    private static Object objectData;
    private static String stringData;
    private static Boolean booleanData;

    private static String errMessage;
    private static Integer exceptionCode;
    private static String exceptionMessage;
    private static Throwable exceptionCause;


    private static ArrayList arrListData;
    private static HashMap<String, Object> hashMapData;
    private static ArrayList<HashMap<String, Object>> arrListHMData;

    private static ResponseUtil instance;

    private ResponseUtil() {

        this.status = true;
        this.exceptionCode = null;
        this.exceptionMessage = null;
        this.booleanData = null;
        this.stringData = null;
        this.intData = null;
        this.arrListData = null;
        this.arrListHMData = null;
        this.hashMapData = null;
        this.objectData = null;
        this.exceptionCause = null;
        this.errMessage = null;
        this.bytesData = null;
    }

    public static ResponseUtil getInstance() {
        ResponseUtil.instance = new ResponseUtil();
        return ResponseUtil.instance;
    }

    public static Boolean getStatus() {
        return status;
    }

    public static void setStatus(Boolean status) {
        ResponseUtil.status = status;
    }

    public static byte[] getBytesData() {
        return bytesData;
    }

    public static void setBytesData(byte[] bytesData) {
        ResponseUtil.bytesData = bytesData;
    }

    public static Integer getExceptionCode() {
        return exceptionCode;
    }

    public static void setExceptionCode(Integer exceptionCode) {
        ResponseUtil.exceptionCode = exceptionCode;
    }

    public static String getExceptionMessage() {
        return exceptionMessage;
    }

    public static void setExceptionMessage(String exceptionMessage) {
        ResponseUtil.exceptionMessage = exceptionMessage;
    }

    public static Boolean getBooleanData() {
        return booleanData;
    }

    public static void setBooleanData(Boolean booleanData) {
        ResponseUtil.booleanData = booleanData;
    }

    public static String getStringData() {
        return stringData;
    }

    public static void setStringData(String stringData) {
        ResponseUtil.stringData = stringData;
    }

    public static Integer getIntData() {
        return intData;
    }

    public static void setIntData(Integer intData) {
        ResponseUtil.intData = intData;
    }

    public static HashMap<String, Object> getHashMapData() {
        return hashMapData;
    }

    public static void setHashMapData(HashMap<String, Object> hashMapData) {
        ResponseUtil.hashMapData = hashMapData;
    }

    public static Object getObjectData() {
        return objectData;
    }

    public static void setObjectData(Object objectData) {
        ResponseUtil.objectData = objectData;
    }

    public static ArrayList getArrListData() {
        return arrListData;
    }

    public static void setArrListData(ArrayList arrListData) {
        ResponseUtil.arrListData = arrListData;
    }

    public static ArrayList<HashMap<String, Object>> getArrListHMData() {
        return arrListHMData;
    }

    public static void setArrListHMData(ArrayList<HashMap<String, Object>> arrListHMData) {
        ResponseUtil.arrListHMData = arrListHMData;
    }

    public static Throwable getExceptionCause() {
        return exceptionCause;
    }

    public static void setExceptionCause(Throwable exceptionCause) {
        ResponseUtil.exceptionCause = exceptionCause;
    }

    public static String getErrMessage() {
        return errMessage;
    }

    public static void setErrMessage(String errMessage) {
        ResponseUtil.errMessage = errMessage;
    }

}
