package com.example.sql.SqlExample.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

@Controller
@RequiredArgsConstructor
public class ExampleController {
    private static final String GET_USER_SQL = "SELECT id, name FROM users WHERE id = ?";
    private static final String IS_SUCCESS_ATTRIBUTE_NAME = "isSuccess";
    private static final String RESULT_ATTRIBUTE_NAME = "result";
    private static final String TEMPLATE_NAME = "page";

    private final JdbcTemplate jdbcTemplate;

    @GetMapping("/")
    public ModelAndView makeRequest(@RequestParam(value = "id", required = false) String id,
                            @RequestParam(value = "Submit", required = false) String submit) {
        ModelAndView modelAndView = new ModelAndView(TEMPLATE_NAME);

        if (id == null || submit == null) {
            modelAndView.addObject(IS_SUCCESS_ATTRIBUTE_NAME, null);
            return modelAndView;
        }

        long idParam;
        try {
            idParam = Long.parseLong(id);
        } catch (NumberFormatException e) {
            modelAndView.addObject(IS_SUCCESS_ATTRIBUTE_NAME, false);
            modelAndView.setStatus(HttpStatus.NOT_FOUND);
            return modelAndView;
        }
        var result = jdbcTemplate.queryForRowSet(GET_USER_SQL, idParam);
        if (result.next()) {
            modelAndView.addObject(RESULT_ATTRIBUTE_NAME,
                new String[] {result.getString("id"), result.getString("name")});
            modelAndView.addObject(IS_SUCCESS_ATTRIBUTE_NAME, true);
        } else {
            modelAndView.addObject(IS_SUCCESS_ATTRIBUTE_NAME, false);
            modelAndView.setStatus(HttpStatus.NOT_FOUND);
        }
        return modelAndView;
    }
}
