package org.java.spring.repo;

import java.util.List;

import org.java.spring.pojo.Ingrediente;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface IngredienteRepository extends JpaRepository<Ingrediente, Integer> {

	
	public abstract List<Ingrediente> findByNomeContaining(String q);
}
