package aux;

public class VisualSignature {
    private int page;
    private int x;
    private int y;

    public VisualSignature(int page, int x, int y) {
        this.page = page;
        this.x = x;
        this.y = y;
    }

    public VisualSignature(int x, int y) {
        this.x = x;
        this.y = y;
        this.page = -1;
    }


    public int getPage() {
        return page;
    }

    public void setPage(int page) {
        this.page = page;
    }

    public int getX() {
        return x;
    }

    public void setX(int x) {
        this.x = x;
    }

    public int getY() {
        return y;
    }

    public void setY(int y) {
        this.y = y;
    }



}
