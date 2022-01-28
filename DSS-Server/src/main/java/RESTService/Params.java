package RESTService;

import java.util.Optional;

public class Params {
    private String userid;
    private String pin;
    private Integer page;
    private Integer x;
    private Integer y;

    public void setUserid(String userid) {
        this.userid = userid;
    }

    public void setPin(String pin) {
        this.pin = pin;
    }

    public void setPage(Integer page) {
        this.page = page;
    }

    public void setX(Integer x) {
        this.x = x;
    }

    public void setY(Integer y) {
        this.y = y;
    }

    public String getUserid() {
        return userid;
    }

    public String getPin() {
        return pin;
    }

    public Integer getPage() {
        return page;
    }

    public Integer getX() {
        return x;
    }

    public Integer getY() {
        return y;
    }

}
