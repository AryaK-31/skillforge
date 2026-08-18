package com.skillforge.authservice.mapper;

import com.skillforge.authservice.dto.request.RegisterRequest;
import com.skillforge.authservice.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface AuthMapper {

    User toUser(RegisterRequest request);

}