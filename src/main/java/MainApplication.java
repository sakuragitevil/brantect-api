import api.ApiFilter;
import api.user.UserController;
import org.glassfish.jersey.media.multipart.MultiPartFeature;
import javax.ws.rs.core.Application;
import java.util.HashSet;
import java.util.Set;

/**
 * Created by Thuan.Evi on 1/3/2017.
 */
public class MainApplication extends Application {
    //The method returns a non-empty collection with classes, that must be included in the published JAX-RS application
    @Override
    public Set<Class<?>> getClasses() {
        HashSet h = new HashSet<Class<?>>();
        h.add(ApiFilter.class);
        h.add(UserController.class);
        h.add(MultiPartFeature.class);
        return h;
    }
}
