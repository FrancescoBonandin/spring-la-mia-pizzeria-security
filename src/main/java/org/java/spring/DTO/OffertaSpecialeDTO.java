package org.java.spring.DTO;

import java.time.LocalDate;

import org.hibernate.validator.constraints.Length;
import org.springframework.format.annotation.DateTimeFormat;

import jakarta.persistence.Column;
import jakarta.validation.constraints.FutureOrPresent;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

public class OffertaSpecialeDTO {

	@NotNull
	@Positive
	@NotBlank
	public int pizza_id;
	
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

	public int getPizza_id() {
		return pizza_id;
	}

	public void setPizza_id(int pizza_id) {
		this.pizza_id = pizza_id;
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
