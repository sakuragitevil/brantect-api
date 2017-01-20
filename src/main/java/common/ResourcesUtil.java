package common;

import org.apache.commons.io.FileUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Created by Sarm_Brights on 1/4/2017.
 */
public class ResourcesUtil {

    private static String resourcePath = "";
    private static HttpServletRequest httpRequest;

    private static ResourcesUtil instance;

    public static ResourcesUtil getInstance(HttpServletRequest httpRequest) {
        ResourcesUtil.instance = new ResourcesUtil(httpRequest);
        return ResourcesUtil.instance;
    }

    private ResourcesUtil(HttpServletRequest httpRequest) {
        HttpSession session = httpRequest.getSession(false);
        this.resourcePath = session.getAttribute("realPath").toString() + "WEB-INF/classes/resources/";
        this.httpRequest = httpRequest;
    }

    /**
     * @param msgCode
     * @return resource value
     * @throws IOException
     */
    public ResponseUtil getMessage(String msgCode) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            HttpSession session = httpRequest.getSession(false);
            String acceptLanguage = session.getAttribute("acceptLanguage").toString();
            String fileName = this.resourcePath + "languages_" + acceptLanguage + ".properties";
            File resourceFile = new File(fileName);
            if (!resourceFile.exists()) {
                responseUtil.setStatus(false);
                responseUtil.setStringData(null);
                responseUtil.setErrMessage("KeyLang File not found");
                return responseUtil;
            }

            Properties prop = new Properties();
            FileInputStream inputStream = FileUtils.openInputStream(resourceFile);
            prop.load(inputStream);

            // get the property value and print it out
            String msgValue = prop.getProperty(msgCode);
            responseUtil.setStringData(msgValue);

        } catch (IOException e) {
            responseUtil.setStatus(false);
            responseUtil.setStringData(null);
            responseUtil.setExceptionCause(e.getCause());
        }
        return responseUtil;
    }

    /**
     * @param configCode
     * @return resource value
     * @throws IOException
     */
    public ResponseUtil getSystemConfig(String configCode) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            String fileName = this.resourcePath + "system.properties";
            File resourceFile = new File(fileName);
            if (!resourceFile.exists()) {
                responseUtil.setStatus(false);
                responseUtil.setStringData(null);
                responseUtil.setErrMessage("System File not found");
                return responseUtil;
            }

            Properties prop = new Properties();
            FileInputStream inputStream = FileUtils.openInputStream(resourceFile);
            prop.load(inputStream);

            // get the property value and print it out
            String msgValue = prop.getProperty(configCode);
            responseUtil.setStringData(msgValue);

        } catch (IOException e) {
            responseUtil.setStatus(false);
            responseUtil.setStringData(null);
            responseUtil.setExceptionCause(e.getCause());
        }
        return responseUtil;
    }
}
