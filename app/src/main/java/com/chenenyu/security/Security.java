package com.chenenyu.security;

/**
 * <p>
 * Created by Cheney on 2017/3/15.
 */
public class Security {
    static {
        System.loadLibrary("security");
    }

    public static native String getSecret();
}
