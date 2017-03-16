package com.chenenyu.security;

import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        TextView sign = (TextView) findViewById(R.id.text_sign1);
        sign.setText(getSign());

        TextView secret = (TextView) findViewById(R.id.text_secret);
        secret.setText(Security.getSecret());
    }

    /**
     * 展示了如何用Java代码获取签名
     */
    private String getSign() {
        try {
            // 下面几行代码展示如何任意获取Context对象，在jni中也可以使用这种方式
//            Class<?> activityThreadClz = Class.forName("android.app.ActivityThread");
//            Method currentApplication = activityThreadClz.getMethod("currentApplication");
//            Application application = (Application) currentApplication.invoke(null);
//            PackageManager pm = application.getPackageManager();
//            PackageInfo pi = pm.getPackageInfo(application.getPackageName(), PackageManager.GET_SIGNATURES);

            PackageManager pm = getPackageManager();
            PackageInfo pi = pm.getPackageInfo(getPackageName(), PackageManager.GET_SIGNATURES);
            Signature[] signatures = pi.signatures;
            Signature signature0 = signatures[0];
            return signature0.toCharsString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}
