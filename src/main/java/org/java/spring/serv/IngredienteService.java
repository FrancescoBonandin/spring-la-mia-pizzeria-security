package org.java.spring.serv;

import java.util.List;

import org.java.spring.pojo.Ingrediente;
import org.java.spring.repo.IngredienteRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class IngredienteService {
	
	@Autowired
	private IngredienteRepository ingredienteRepo;
	
	public List<Ingrediente> findAll() {
		
		return ingredienteRepo.findAll();
	}
	
	public Ingrediente findById(int id) {
		
		return ingredienteRepo.findById(id).get();
	}
	
	public List<Ingrediente> findByNome(String q) {
		
		return ingredienteRepo.findByNomeContaining(q);
	}
	
	public void save(Ingrediente ingrediente) {
		
		ingredienteRepo.save(ingrediente);
	}
	
	public void delete(Ingrediente ingrediente) {
		
		ingredienteRepo.delete(ingrediente);
		
	}
	
	public void deleteById(int id) {
		
		ingredienteRepo.deleteById(id);
		
	}

}
