package org.mcs.finaljwtversion.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MainController {

    @GetMapping("/secured")
    public String securedApi(){
        return "this is response from secured Api";
    }

    @GetMapping("/unsecured")
    public String unsecuredApi(){
        return "this is response from unsecured Api";
    }

    @GetMapping("/admin")
    public String adminApi(){
        return "this is response from admin Api";
    }
}
