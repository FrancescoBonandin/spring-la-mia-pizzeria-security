package org.java.spring.pojo;

import java.time.LocalDate;

import org.hibernate.validator.constraints.Length;
import org.springframework.format.annotation.DateTimeFormat;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotNull;

@Entity

public class OffertaSpeciale {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;
	
	@Column(columnDefinition = "DATE")
	@FutureOrPresent
	@NotNull
	@DateTimeFormat(pattern = "dd/MM/yyyy")
	public LocalDate dataDiInizio;
	
	@Column(columnDefinition = "DATE")
	@FutureOrPresent
	@NotNull
	@DateTimeFormat(pattern = "dd/MM/yyyy")
	public LocalDate dataDiFine;
	
	@Column(length=30, nullable=false)
	@Length(min = 3, max = 30)
	@NotNull
	public String titolo;
	
	@ManyToOne
	@JoinColumn(name="pizza_id", nullable=false)
	private Pizza pizza;
	
	

	public OffertaSpeciale() {}
	
	public OffertaSpeciale(LocalDate dataDiInizio, LocalDate dataDiFine, String titolo, Pizza pizza) {
		
		setDataDiInizio(dataDiInizio);
		setDataDiFine(dataDiFine);
		setTitolo(titolo);
		setPizza(pizza);
	}
	
	
	
	public Integer getId() {
		return id;
	}

	public void setId(Integer id) {
		this.id = id;
	}


	public Pizza getPizza() {
		return pizza;
	}
	
	public void setPizza(Pizza pizza) {
		this.pizza = pizza;
	}
	
	public LocalDate getDataDiInizio() {
		return dataDiInizio;
	}
	public void setDataDiInizio(LocalDate dataDiInizio) {
		this.dataDiInizio = dataDiInizio;
	}
	public LocalDate getDataDiFine() {
		return dataDiFine;
	}
	public void setDataDiFine(LocalDate dataDiFine) {
		this.dataDiFine = dataDiFine;
	}
	public String getTitolo() {
		return titolo;
	}
	public void setTitolo(String titolo) {
		this.titolo = titolo;
	}
	
	
	

}
