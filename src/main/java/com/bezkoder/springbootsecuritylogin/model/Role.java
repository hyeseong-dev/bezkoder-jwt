package com.bezkoder.springbootsecuritylogin.model;

import jakarta.persistence.*;

@Entity
@Table(name = "roles")
public class Role {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole name;

    // Default constructor
    public Role() {
    }

    // Parameterized constructor
    public Role(ERole name) {
        this.name = name;
    }

    // Getter for 'id'
    public Integer getId() {
        return id;
    }

    // Setter for 'id'
    public void setId(Integer id) {
        this.id = id;
    }

    // Getter for 'name'
    public ERole getName() {
        return name;
    }

    // Setter for 'name'
    public void setName(ERole name) {
        this.name = name;
    }
}
