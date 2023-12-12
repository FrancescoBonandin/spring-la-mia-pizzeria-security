package org.java.spring.serv;

import java.util.List;

import org.java.spring.pojo.Pizza;
import org.java.spring.repo.PizzaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PizzaService  {

	
	@Autowired
	private PizzaRepository pizzaRepository;
	
	public List<Pizza> findAll() {
		
		return pizzaRepository.findAll();
	}
	
	public Pizza findById(int id) {
		
		return pizzaRepository.findById(id).get();
	}
	
	
	public List<Pizza> findByNomeOrDescrizione(String q) {
		
		return pizzaRepository.findByNomeContainingOrDescrizioneContaining(q,q);
	}
	
//	-- trying to update a pizza with a private setId (not working)--
	
//	public void updatePizza(int id, String nome, Float prezzo) {
//		
//		Pizza p =findById(id);
//		
//		p.setNome(nome);
//		p.setPrezzo(prezzo);
//		
//		save(p);
//		
//		
//	}
//	
//	public void updatePizza(int id, String nome, Float prezzo, String descrizione) {
//		
//		Pizza p =findById(id);
//		
//		p.setNome(nome);
//		p.setPrezzo(prezzo);
//		p.setDescrizione(descrizione);
//		
//		save(p);
//		
//		
//	}
//	
//	public void updatePizza(int id, String nome, Float prezzo, String descrizione, String fotoUrl) {
//		
//		Pizza p = findById(id);
//		
//		p.setNome(nome);
//		p.setPrezzo(prezzo);
//		p.setDescrizione(descrizione);
//		p.setFotoUrl(fotoUrl);
//		
//		save(p);
//		
//		
//	}
	
	public void save(Pizza pizza) {
		
		pizzaRepository.save(pizza);
	}
	
	public void delete(Pizza pizza) {
		
		pizzaRepository.delete(pizza);
		
	}
	
	public void deleteById(int id) {
		
		pizzaRepository.deleteById(id);
		
	}
}


