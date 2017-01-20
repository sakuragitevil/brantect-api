package common;

import org.postgresql.jdbc3.Jdbc3PoolingDataSource;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;

/**
 * Created by Thuan.Evi on 12/21/2016.
 */
public final class PostgreSql {

    private String dbHost = "";
    private String dbPort = "";
    private String dbName = "";
    private String dbUser = "";
    private String dbPass = "";

    private static HttpServletRequest httpRequest;
    private Jdbc3PoolingDataSource dataSource = null;
    private Connection connection = null;
    public ResponseUtil responseUtil = null;

    private static PostgreSql instance;

    private PostgreSql(HttpServletRequest httpRequest) {

        this.httpRequest = httpRequest;
        ResourcesUtil resourcesUtil = ResourcesUtil.getInstance(httpRequest);
        this.responseUtil = resourcesUtil.getSystemConfig("DB_HOST");
        if (responseUtil.getStatus() == true)
            this.dbHost = responseUtil.getStringData();

        this.responseUtil = resourcesUtil.getSystemConfig("DB_NAME");
        if (responseUtil.getStatus() == true)
            this.dbName = responseUtil.getStringData();

        this.responseUtil = resourcesUtil.getSystemConfig("DB_USER");
        if (responseUtil.getStatus() == true)
            this.dbUser = responseUtil.getStringData();

        this.responseUtil = resourcesUtil.getSystemConfig("DB_PASS");
        if (responseUtil.getStatus() == true)
            this.dbPass = responseUtil.getStringData();

        if (this.responseUtil.getStatus() == true) {
            this.connect();
            if (this.responseUtil.getStatus() == true)
                this.execute("SET SCHEMA " + Constant.DBSCHEMA);
            else
                this.responseUtil.setErrMessage(resourcesUtil.getMessage("MSG2").getStringData());
        }

    }

    public static PostgreSql getInstance(HttpServletRequest httpRequest) {
        if (PostgreSql.instance == null) {
            PostgreSql.instance = new PostgreSql(httpRequest);
        }
        return PostgreSql.instance;
    }

    /**
     * get connection
     *
     * @return
     */
    public Connection getConnection() {
        return this.connection;
    }

    /**
     *
     */
    private void connect() {
        this.responseUtil = ResponseUtil.getInstance();
        String JNDINAME = Constant.DEPLOYED ? Constant.PROD_JNDINAME : Constant.TEST_JNDINAME;
        if (this.dataSource == null) {
            try {

                this.dataSource = new Jdbc3PoolingDataSource();
                this.dataSource.setDataSourceName(JNDINAME);
                this.dataSource.setDatabaseName(this.dbName);
                this.dataSource.setServerName(this.dbHost);
                this.dataSource.setUser(this.dbUser);
                this.dataSource.setPassword(this.dbPass);
                this.dataSource.setMaxConnections(10);
                new InitialContext().rebind(JNDINAME, this.dataSource);

            } catch (NamingException e) {
                responseUtil.setStatus(false);
                responseUtil.setExceptionCause(e.getCause());
                responseUtil.setExceptionMessage(e.getMessage());
            }
        }

        try {
            this.dataSource = (Jdbc3PoolingDataSource) new InitialContext().lookup(JNDINAME);
            this.connection = this.dataSource.getConnection();
        } catch (SQLException e) {
            this.responseUtil = handleSqlException(e, responseUtil);
        } catch (NamingException e) {
            this.responseUtil.setStatus(false);
            this.responseUtil.setExceptionCause(e.getCause());
            this.responseUtil.setExceptionMessage(e.getMessage());
        }
    }

    /**
     *
     */
    public ResponseUtil commit() {
        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {
            this.connection.commit();
        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }
        return responseUtil;
    }

    /**
     *
     */
    public ResponseUtil rollback() {
        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {
            this.connection.rollback();
        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }
        return responseUtil;
    }

    /**
     * @param sql
     * @return
     */
    public ResponseUtil execute(String sql) {
        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            Statement stmt = this.connection.createStatement();
            int result = stmt.executeUpdate(sql);
            responseUtil.setIntData(result);
            stmt.close();

        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }
        return responseUtil;
    }

    /**
     * @param sql
     * @param parameters
     * @return
     */
    public ResponseUtil execute(String sql, ArrayList<Object> parameters) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            PreparedStatement pstmt = this.connection.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT);
            for (int i = 0; i < parameters.size(); i++) {
                if (parameters.get(i) == null) {
                    pstmt.setNull(i + 1, Types.INTEGER);
                } else {
                    pstmt.setObject(i + 1, parameters.get(i));
                }
            }
            int result = pstmt.executeUpdate();
            responseUtil.setIntData(result);
            pstmt.close();
        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }
        return responseUtil;
    }

    /**
     * @param sql
     * @return
     */
    public ResponseUtil fetch(String sql) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            ArrayList<HashMap<String, Object>> results = new ArrayList<HashMap<String, Object>>();
            PreparedStatement stmt = this.connection.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT);
            ResultSet rs = stmt.executeQuery();
            responseUtil = this.doFetch(rs, results);
            stmt.close();

        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }

        return responseUtil;
    }

    /**
     * @param sql
     * @param parameters
     * @return
     */
    public ResponseUtil fetch(String sql, ArrayList<Object> parameters) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            ArrayList<HashMap<String, Object>> results = new ArrayList<HashMap<String, Object>>();
            // Bind parameters to statement.
            PreparedStatement pstmt = this.connection.prepareStatement(sql, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY, ResultSet.HOLD_CURSORS_OVER_COMMIT);
            for (int i = 0; i < parameters.size(); i++) {
                pstmt.setObject(i + 1, parameters.get(i));
            }

            ResultSet rs = pstmt.executeQuery();
            this.doFetch(rs, results);
            pstmt.close();

            responseUtil.setArrListHMData(results);

        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
        }

        return responseUtil;
    }

    /**
     * Fetches the results from the ResultSet into the given ArrayList.
     *
     * @param rs
     * @param results
     * @throws SQLException
     */
    private ResponseUtil doFetch(ResultSet rs, ArrayList<HashMap<String, Object>> results) {

        ResponseUtil responseUtil = ResponseUtil.getInstance();
        try {

            ArrayList<String> cols = new ArrayList<String>();

            ResultSetMetaData rsmd = rs.getMetaData();
            int numCols = rsmd.getColumnCount();

            for (int i = 1; i <= numCols; i++) {
                cols.add(rsmd.getColumnName(i));
            }

            while (rs.next()) {
                HashMap<String, Object> result = new HashMap<String, Object>();
                for (int i = 1; i <= numCols; i++) {
                    result.put(cols.get(i - 1), rs.getObject(i));
                }
                results.add(result);
            }
            responseUtil.setArrListHMData(results);

            rs.close();
        } catch (SQLException e) {
            responseUtil = handleSqlException(e, responseUtil);
            responseUtil.setArrListHMData(null);
        }
        return responseUtil;
    }

    private ResponseUtil handleSqlException(SQLException e, ResponseUtil responseUtil) {
        responseUtil.setStatus(false);
        responseUtil.setExceptionCause(e.getCause());
        responseUtil.setExceptionCode(e.getErrorCode());
        responseUtil.setExceptionMessage(e.getMessage());
        return responseUtil;
    }
}
