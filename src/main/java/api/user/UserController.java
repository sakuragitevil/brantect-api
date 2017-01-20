package api.user;

import com.google.gson.Gson;
import common.ResponseUtil;
import org.glassfish.jersey.media.multipart.BodyPartEntity;
import org.glassfish.jersey.media.multipart.FormDataBodyPart;
import org.glassfish.jersey.media.multipart.FormDataMultiPart;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/**
 * Created by Thuan.Evi on 1/4/2017.
 */
@Path("/user")
public class UserController {

    @Context
    HttpServletRequest httpRequest;

    /**
     * Method handling HTTP GET requests. The returned object will be sent
     * to the client as "text/plain" media type.
     *
     * @return String that will be returned as a text/plain response.
     */
    @POST
    @Path("/authenticate")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public Response authenticate() {
        return Response.status(200).entity("OK").build();
//        ResponseUtil responseUtil = UserModel.getInstance(httpRequest).authenticate();
//        if (responseUtil.getStatus() == true)
//            return Response.status(200).entity(responseUtil.getStringData()).build();
//        else
//            return Response.status(200).entity(responseUtil.getErrMessage()).build();
    }

    /**
     * @param formDataMultiPart
     * @return Response
     */
    @POST
    @Path("/upload")
    @Produces(MediaType.MULTIPART_FORM_DATA)
    @Consumes(MediaType.MULTIPART_FORM_DATA)
    public Response uploadFile(final FormDataMultiPart formDataMultiPart) {

        UserModel userModel = UserModel.getInstance(httpRequest);
        FormDataBodyPart formDataBodyPart = formDataMultiPart.getField("count");
        List<FormDataBodyPart> formDataBodyPartList = formDataMultiPart.getFields("files");

        String count = formDataBodyPart.getValue();
        /* Save multiple files */
        for (int i = 0; i < formDataBodyPartList.size(); i++) {
            BodyPartEntity bodyPartEntity = (BodyPartEntity) formDataBodyPartList.get(i).getEntity();
            String fileName = formDataBodyPartList.get(i).getContentDisposition().getFileName();
            InputStream inputStream = bodyPartEntity.getInputStream();
            ResponseUtil responseUtil = userModel.uploadFile(inputStream, fileName);
            if (responseUtil.getStatus() == false)
                return Response.status(200).entity(responseUtil.getErrMessage()).build();
        }
        return Response.status(200).entity("ok").build();
    }

    /**
     * @return Response
     */
    @GET
    @Path("/all")
    @Produces(MediaType.TEXT_PLAIN)
    @Consumes(MediaType.TEXT_PLAIN)
    public Response getAllUsers() {
        UserModel userModel = UserModel.getInstance(httpRequest);
        ResponseUtil responseUtil = userModel.getAllUsers();
        if (responseUtil.getStatus() == false)
            return Response.status(200).entity(responseUtil.getErrMessage()).build();
        ArrayList<HashMap<String, Object>> results = responseUtil.getArrListHMData();
        return Response.status(200).entity(new Gson().toJson(results)).build();
    }
}
