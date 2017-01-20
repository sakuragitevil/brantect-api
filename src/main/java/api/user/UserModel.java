package api.user;

import com.google.common.hash.Hashing;
import common.PostgreSql;
import common.ResourcesUtil;
import common.ResponseUtil;
import common.TokenUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by Sarm_Brights on 1/4/2017.
 */
public class UserModel {

    private static UserModel instance;
    private static PostgreSql postgreSql;
    private static HttpServletRequest httpRequest;

    private UserModel(HttpServletRequest httpRequest) {
        this.httpRequest = httpRequest;
        postgreSql = PostgreSql.getInstance(this.httpRequest);
    }

    public static UserModel getInstance(HttpServletRequest httpRequest) {
        UserModel.instance = new UserModel(httpRequest);
        return UserModel.instance;
    }

    public ResponseUtil authenticate() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            if (postgreSql.responseUtil.getStatus() == false)
                return postgreSql.responseUtil;

            ResourcesUtil resourcesUtil = ResourcesUtil.getInstance(httpRequest);
            TokenUtil tokenUtil = TokenUtil.getInstance(httpRequest);
            HttpSession session = httpRequest.getSession(false);
            String secretKey = session.getAttribute("credentials").toString();
            final String[] arrCredentials = secretKey.split(":", 2);

            ArrayList<Object> arrPparams = new ArrayList<Object>();
            arrPparams.add(arrCredentials[0]);
            arrPparams.add(Hashing.sha256().hashString(arrCredentials[1], Charset.forName("UTF-8")).toString());

            responseUtil = postgreSql.fetch("SELECT * FROM mst_user WHERE login_id = ? AND pwd = ?", arrPparams);
            if (responseUtil.getStatus() == false) {
                responseUtil.setBooleanData(false);
                return responseUtil;
            }

            ArrayList<HashMap<String, Object>> results = responseUtil.getArrListHMData();
            if (results.isEmpty()) {
                responseUtil.setBooleanData(false);
                responseUtil.setErrMessage(resourcesUtil.getMessage("MSG3").getStringData());
                return responseUtil;
            }

            if (!tokenUtil.rsaFileExists()) {

                responseUtil = tokenUtil.rsaGenerator();
                if (results.isEmpty()) {
                    responseUtil.setBooleanData(false);
                    return responseUtil;
                }
            }

            responseUtil = tokenUtil.jwtGenerator();
            if (results.isEmpty()) {
                responseUtil.setBooleanData(false);
                return responseUtil;
            }

        } catch (Exception e) {
            responseUtil.setStatus(false);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    public ResponseUtil getAllUsers() {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            if (postgreSql.responseUtil.getStatus() == false)
                return postgreSql.responseUtil;

            responseUtil = postgreSql.fetch("select * from mst_user");
            if (responseUtil.getStatus() == false)
                return responseUtil;
            ArrayList<HashMap<String, Object>> results = responseUtil.getArrListHMData();
            responseUtil.setArrListHMData(results);

        } catch (Exception e) {
            responseUtil.setStatus(false);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }

    public ResponseUtil uploadFile(InputStream inputStream, String fileName) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            HttpSession session = httpRequest.getSession(false);
            String realPath = session.getAttribute("realPath").toString();
            int read = 0;
            byte[] bytes = new byte[1024];
            OutputStream outpuStream = new FileOutputStream(new File(realPath + "WEB-INF/classes/" + fileName));
            while ((read = inputStream.read(bytes)) != -1) {
                outpuStream.write(bytes, 0, read);
            }
            outpuStream.flush();
            outpuStream.close();

        } catch (IOException e) {
            responseUtil.setStatus(false);
            responseUtil.setExceptionCause(e.getCause());
            responseUtil.setExceptionMessage(e.getMessage());
        }
        return responseUtil;
    }
}
