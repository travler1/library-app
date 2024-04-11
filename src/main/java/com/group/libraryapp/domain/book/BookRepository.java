package com.group.libraryapp.domain.book;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
                                                    //Book에 관한 것, id타입 Long
public interface BookRepository extends JpaRepository<Book, Long> {

  Optional<Book> findByName(String name);

}
