package org.mcs.finaljwtversion.repository;

import org.mcs.finaljwtversion.model.UserEntity;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserEntityRepository extends CrudRepository<UserEntity, Long> {
    UserEntity findUserEntityByName(String name);
}
