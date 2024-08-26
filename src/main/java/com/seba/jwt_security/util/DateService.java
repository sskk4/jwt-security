package com.seba.jwt_security.util;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

public class DateService {

    public static LocalDateTime getDateNow() {
        return LocalDateTime.now();
    }
    public static LocalDateTime addDaysToDate(LocalDateTime dateTime, int days) {
        return dateTime.plusDays(days);
    }
    public static Date addFiveMinutesToDate(LocalDateTime dateTime) {
        return convertToDate(dateTime.plusMinutes(60));
    }
    public static Date convertToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }
}
