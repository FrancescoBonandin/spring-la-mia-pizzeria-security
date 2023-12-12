package org.java.spring.controller;

import java.util.List;

import org.java.spring.pojo.Ingrediente;
import org.java.spring.pojo.Pizza;
import org.java.spring.serv.IngredienteService;
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
public class IngredienteController {
	
	@Autowired
	private IngredienteService ingredienteService;
	
	@Autowired
	private PizzaService pizzaService;

	@GetMapping("/ingrediente/")
	public String routeIndex(Model model, @RequestParam(required=false) String q ) {
		
		List<Ingrediente> ingredienti = q==null
							? ingredienteService.findAll()
							: ingredienteService.findByNome(q);
		
		model.addAttribute("ingredienti",ingredienti);
		model.addAttribute("q", q == null ? "" : q);
		
		return "ingrediente/index";
		
	}
	
	@GetMapping("/ingrediente/create")
	
	public String routeCreate(Model model) {
		
		
		Ingrediente ingrediente = new Ingrediente();
		
		model.addAttribute("ingrediente",ingrediente);
		model.addAttribute("title", "Create");
		
		return "ingrediente/form";
	}
	
	@PostMapping("/ingrediente/create")
	public String storeIngrediente(
			Model model,
			@Valid @ModelAttribute Ingrediente ingrediente, 
			BindingResult bindingResult) {
		
//		System.out.println("ingrediente:\n" + ingrediente);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			model.addAttribute("ingrediente", ingrediente);
			return "ingrediente/form";
		}
		
		else {
			
			try {
					
				ingredienteService.save(ingrediente);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("ingrediente", "nome", ingrediente.getNome(), false, null, null, "Nome must be unique"));
				model.addAttribute("ingrediente", ingrediente);
				return "ingrediente/form";
			}
			
			return "redirect:/ingrediente/";
		}
		
	}
	
	@GetMapping("/ingrediente/{id}")
	public String routeShow(Model model, @PathVariable int id) {
		
		Ingrediente ingrediente = ingredienteService.findById(id);
		
		model.addAttribute("ingrediente",ingrediente);
		
		return "ingrediente/show";
		
	}
	
	@GetMapping("/ingrediente/edit/{id}")
	public String routeEdit(Model model, @PathVariable int id) {
		
		Ingrediente ingrediente = new Ingrediente();
		
		model.addAttribute("ingrediente",ingrediente);
		model.addAttribute("title", "Edit");
		
		return "ingrediente/form";
	}
	
	@PostMapping("/ingrediente/edit/{id}")
	public String updateIngrediente(
			Model model,
			@Valid @ModelAttribute Ingrediente ingrediente, 
			BindingResult bindingResult) {
		
		
//		System.out.println("ingrediente:\n" + ingrediente);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			model.addAttribute("ingrediente", ingrediente);
			model.addAttribute("title", "edit");
			
			return "ingrediente/form";
		}
		
		else {
			
			try {
			
//				--if set id is Private?? Maybe something like this but improved(this doesn't work) --
//				ingredienteService.updateIngrediente(ingrediente.getId(), ingrediente.getNome(), ingrediente.getPrezzo(), ingrediente.getDescrizione(), ingrediente.getFotoUrl());
				
				ingredienteService.save(ingrediente);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("ingrediente", "nome", ingrediente.getNome(), false, null, null, "Nome must be unique"));
				model.addAttribute("ingrediente", ingrediente);
				model.addAttribute("title", "edit");
				
				return "ingrediente/form";
			}
			
			return "redirect:/ingrediente/";
		}
		
	}
	
	@PostMapping("/ingrediente/delete/{id}")
	public String routeDelete( RedirectAttributes redirectAttribute,  @PathVariable int id) {
		
		Ingrediente ingrediente = ingredienteService.findById(id);
		
		//prendi tutte le pizze associate all ingrediente e svuota
		//la lista dei loro ingredienti(droppa tutte le relazioni)
		//ingrediente.getPizzas().forEach(pizza->pizza.clearIngredienti());
		
		//prendi tutte le pizze associate all ingrediente e rimuovi
		//dalla lista dei loro ingredienti il singolo ingrediente(droppa la relazione con ingrediente)
		ingrediente.getPizzas().forEach(pizza->pizza.getIngredienti().remove(ingrediente));
		
		ingrediente.clearPizzas();
		ingredienteService.save(ingrediente);
		
		
		ingredienteService.delete(ingrediente);
		
		redirectAttribute.addFlashAttribute("deletedIngrediente", ingrediente);
		
//		System.out.println(ingrediente.getNome());
		
		return "redirect:/ingrediente/";
	}

}
