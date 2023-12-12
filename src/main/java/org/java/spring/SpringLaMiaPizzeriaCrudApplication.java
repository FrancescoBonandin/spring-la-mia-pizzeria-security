package org.java.spring;

import java.time.LocalDate;
import java.util.List;
import java.util.Random;

import org.java.spring.pojo.Ingrediente;
import org.java.spring.pojo.OffertaSpeciale;
import org.java.spring.pojo.Pizza;
import org.java.spring.serv.IngredienteService;
import org.java.spring.serv.OffertaSpecialeService;
import org.java.spring.serv.PizzaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringLaMiaPizzeriaCrudApplication implements CommandLineRunner {
	
	@Autowired
	private PizzaService pizzaService;
	
	@Autowired
	private OffertaSpecialeService offertaSpecialeService;
	
	@Autowired
	private IngredienteService ingredienteService;

	public static void main(String[] args) {
		SpringApplication.run(SpringLaMiaPizzeriaCrudApplication.class, args);
	}
	
	@Override
	public void run(String... args) throws Exception {
		
		Random rnd= new Random();
		
		int num3 = 1;
		
		ingredienteService.save(new Ingrediente("ingrediente-"+ num3++));
		ingredienteService.save(new Ingrediente("ingrediente-"+ num3++));
		ingredienteService.save(new Ingrediente("ingrediente-"+ num3++));
		ingredienteService.save(new Ingrediente("ingrediente-"+ num3++));
		
		List<Ingrediente> ingredienti = ingredienteService.findAll();
		
		int num = 1;
		pizzaService.save(new Pizza("Pizza " + num, "una pizza buona " + num++, 9.90f + 0.1f, "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Pizza_marinara.jpg/260px-Pizza_marinara.jpg", ingredienti.get(rnd.nextInt(0,ingredienti.size()-1))));
		pizzaService.save(new Pizza("Pizza " + num, "una pizza buona " + num++, 9.90f + 0.2f, "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Pizza_marinara.jpg/260px-Pizza_marinara.jpg", ingredienti.get(rnd.nextInt(0,ingredienti.size()-1))));
		pizzaService.save(new Pizza("Pizza " + num, "una pizza buona " + num++, 9.90f + 0.3f, "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Pizza_marinara.jpg/260px-Pizza_marinara.jpg", ingredienti.get(rnd.nextInt(0,ingredienti.size()-1))));
		pizzaService.save(new Pizza("Pizza " + num, "una pizza buona " + num++, 9.90f + 0.4f, "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Pizza_marinara.jpg/260px-Pizza_marinara.jpg", ingredienti.get(rnd.nextInt(0,ingredienti.size()-1))));
		pizzaService.save(new Pizza("Pizza " + num, "una pizza buona " + num++, 9.90f + 0.5f, "https://upload.wikimedia.org/wikipedia/commons/thumb/1/11/Pizza_marinara.jpg/260px-Pizza_marinara.jpg" ));
		
		int num2 = 1;
		
		List<Pizza> pizzas = pizzaService.findAll();
		
	
		
		offertaSpecialeService.save(new OffertaSpeciale( LocalDate.now(), LocalDate.now().plusDays(num2), "Offertona"+num2++,pizzas.get(rnd.nextInt(0,pizzas.size()-1))));
		offertaSpecialeService.save(new OffertaSpeciale( LocalDate.now(), LocalDate.now().plusDays(num2), "Offertona"+num2++,pizzas.get(rnd.nextInt(0,pizzas.size()-1))));
		offertaSpecialeService.save(new OffertaSpeciale( LocalDate.now(), LocalDate.now().plusDays(num2), "Offertona"+num2++,pizzas.get(rnd.nextInt(0,pizzas.size()-1))));
		

		
	}

}
