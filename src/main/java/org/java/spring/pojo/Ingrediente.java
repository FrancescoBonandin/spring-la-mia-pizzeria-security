package org.java.spring.pojo;

import java.util.Arrays;
import java.util.List;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;

@Entity
public class Ingrediente {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	public int id;
	
	public String nome;
	
	@ManyToMany(mappedBy = "ingredienti")
	
	public List<Pizza> pizzas;
	
	public Ingrediente() {}
	
	public Ingrediente(String nome, Pizza...pizzas) {
		
		setNome(nome);
		setPizzas(pizzas);
		
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getNome() {
		return nome;
	}

	public void setNome(String nome) {
		this.nome = nome;
	}

	public List<Pizza> getPizzas() {
		return pizzas;
	}

	public void setPizzas(List<Pizza> pizzas) {
		this.pizzas = pizzas;
	}
	
	public void setPizzas(Pizza... pizzas) {
		setPizzas(Arrays.asList(pizzas));
	}
	
	public void clearPizzas() {
		getPizzas().clear();
	}
	
	
	
	
	

}
