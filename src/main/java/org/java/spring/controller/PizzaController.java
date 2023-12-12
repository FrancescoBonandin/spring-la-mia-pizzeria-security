package org.java.spring.controller;

import java.util.List;

import org.java.spring.pojo.Ingrediente;
import org.java.spring.pojo.OffertaSpeciale;
import org.java.spring.pojo.Pizza;
import org.java.spring.serv.IngredienteService;
import org.java.spring.serv.OffertaSpecialeService;
import org.java.spring.serv.PizzaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.validation.Valid;

@Controller
public class PizzaController {
	
	@Autowired
	private PizzaService pizzaService;
	
	@Autowired
	private OffertaSpecialeService offertaSpecialeService;
	
	@Autowired
	private IngredienteService ingredienteService;

	@GetMapping
	public String routeIndex(Model model, @RequestParam(required=false) String q ) {
		
		List<Pizza> pizzas = q==null
							? pizzaService.findAll()
							: pizzaService.findByNomeOrDescrizione(q);
		
		model.addAttribute("pizzas",pizzas);
		model.addAttribute("q", q == null ? "" : q);
		
		return "pizza/index";
		
	}
	
	@GetMapping("/pizza/create")
	
	public String routeCreate(Model model) {
		
		Pizza pizza = new Pizza();
		List <Ingrediente> ingredienti=ingredienteService.findAll();
		
		model.addAttribute("pizza",pizza);
		model.addAttribute("ingredienti", ingredienti);
		model.addAttribute("title", "Create");
		
		return "pizza/form";
	}
	
	@PostMapping("/pizza/create")
	public String storePizza(
			Model model,
			@Valid @ModelAttribute Pizza pizza, 
			BindingResult bindingResult) {
		
//		System.out.println("pizza:\n" + pizza);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			model.addAttribute("pizza", pizza);
			return "pizza/form";
		}
		
		else {
			
			try {
					
				pizzaService.save(pizza);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("pizza", "nome", pizza.getNome(), false, null, null, "Nome must be unique"));
				model.addAttribute("pizza", pizza);
				return "pizza/form";
			}
			
			return "redirect:/";
		}
		
	}
	
	@GetMapping("/pizza/{id}")
	public String routeShow(Model model, @PathVariable int id) {
		
		Pizza pizza = pizzaService.findById(id);
		
		model.addAttribute("pizza",pizza);
		
		return "pizza/show";
		
	}
	
	@GetMapping("/pizza/edit/{id}")
	public String routeEdit(Model model, @PathVariable int id) {
		
		Pizza pizza = pizzaService.findById(id);
		List <Ingrediente> ingredienti=ingredienteService.findAll();
		
		model.addAttribute("pizza",pizza);
		model.addAttribute("ingredienti", ingredienti);
		model.addAttribute("title", "Edit");
		
		return "pizza/form";
	}
	
	@PostMapping("/pizza/edit/{id}")
	public String updatePizza(
			Model model,
			@Valid @ModelAttribute Pizza pizza, 
			BindingResult bindingResult) {
		
		
//		System.out.println("pizza:\n" + pizza);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			model.addAttribute("pizza", pizza);
			model.addAttribute("title", "edit");
			
			return "pizza/form";
		}
		
		else {
			
			try {
			
//				--if set id is Private?? Maybe something like this but improved(this doesn't work) --
//				pizzaService.updatePizza(pizza.getId(), pizza.getNome(), pizza.getPrezzo(), pizza.getDescrizione(), pizza.getFotoUrl());
				
				pizzaService.save(pizza);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("pizza", "nome", pizza.getNome(), false, null, null, "Nome must be unique"));
				model.addAttribute("pizza", pizza);
				model.addAttribute("title", "edit");
				
				return "pizza/form";
			}
			
			return "redirect:/";
		}
		
	}
	
	@PostMapping("/pizza/delete/{id}")
	public String routeDelete( RedirectAttributes redirectAttribute,  @PathVariable int id) {
		
		Pizza pizza = pizzaService.findById(id);
		
// NON necessario		
//		pizza.clearIngredienti();
//		pizzaService.save(pizza);
		
		pizza.getOffertaSpeciale().forEach(offertaSpecialeService::delete);
		
		pizzaService.delete(pizza);
		
		redirectAttribute.addFlashAttribute("deletedPizza", pizza);
		
//		System.out.println(pizza.getNome());
		
		return "redirect:/";
	}

}
