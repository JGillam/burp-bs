package burp;

import com.professionallyevil.burpbsh.BshExtender;

public class BurpExtender implements IBurpExtender {
    private final BshExtender extender = new BshExtender();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {

        extender.registerExtenderCallbacks(callbacks);
    }
}