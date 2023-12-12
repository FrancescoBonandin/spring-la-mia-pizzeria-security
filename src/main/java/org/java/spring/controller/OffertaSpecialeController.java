package org.java.spring.controller;

import org.java.spring.pojo.OffertaSpeciale;
import org.java.spring.pojo.Pizza;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.validation.Valid;

@Controller

public class OffertaSpecialeController {
	
	
@Autowired

private OffertaSpecialeService offertaSpecialeService ;

@Autowired

private PizzaService pizzaService;
	
	@GetMapping("/pizza/{pizza_id}/offertaSpeciale/create")
	
	public String routeCreate(Model model, @PathVariable int pizza_id) {
		
		OffertaSpeciale offertaSpeciale = new OffertaSpeciale();
		
		model.addAttribute("offertaSpeciale",offertaSpeciale);
		model.addAttribute("title", "Create");
		
		return "offertaSpeciale/form";
	}
	
	@PostMapping("/pizza/{pizza_id}/offertaSpeciale/create")
	public String storeOffertaSpeciale(
			Model model,
			@Valid @ModelAttribute OffertaSpeciale offertaSpeciale, 
			BindingResult bindingResult, @PathVariable int pizza_id) {
		
		Pizza pizza = pizzaService.findById(pizza_id);
		
		offertaSpeciale.setPizza(pizza);
//		System.out.println("offertaSpeciale:\n" + offertaSpeciale);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			model.addAttribute("offertaSpeciale", offertaSpeciale);
			return "offertaSpeciale/form";
		}
		
		else {
			
			try {
				
				
					
				offertaSpecialeService.save(offertaSpeciale);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("offertaSpeciale", "titolo", offertaSpeciale.getTitolo(), false, null, null, "Nome must be unique"));
				model.addAttribute("offertaSpeciale", offertaSpeciale);
				return "offertaSpeciale/form";
			}
			
			return "redirect:/pizza/"+pizza_id;
		}
	}
	
	@GetMapping("/pizza/{pizza_id}/offertaSpeciale/edit/{id}")
	public String routeEdit(Model model,@PathVariable int pizza_id, @PathVariable int id) {
		
		OffertaSpeciale offertaSpeciale = offertaSpecialeService.findById(id);
		
		model.addAttribute("offertaSpeciale",offertaSpeciale);
		model.addAttribute("title", "Edit");
		
		return "offertaSpeciale/form";
	}
	
	@PostMapping("/pizza/{pizza_id}/offertaSpeciale/edit/{id}")
	public String updateOffertaSpeciale(
			Model model,
			@Valid @ModelAttribute OffertaSpeciale offertaSpeciale, 
			BindingResult bindingResult, @PathVariable int pizza_id, @PathVariable int id) {
		
		Pizza pizza = pizzaService.findById(pizza_id);
		offertaSpeciale.setPizza(pizza);
//		System.out.println("offertaSpeciale:\n" + offertaSpeciale);
//		System.out.println("\n---------------\n");
//		System.out.println("Error:\n" + bindingResult);
		
		if (bindingResult.hasErrors()) {
			
			System.out.println(bindingResult);
			System.out.println(model);
			model.addAttribute("offertaSpeciale", offertaSpeciale);
			model.addAttribute("title", "Edit");
			
			return "offertaSpeciale/form";
		}
		
		else {
			
			try {
			
//				--if set id is Private?? Maybe something like this but improved(this doesn't work) --
//				offertaSpecialeService.updateOffertaSpeciale(offertaSpeciale.getId(), offertaSpeciale.getTitolo(), offertaSpeciale.getPrezzo(), offertaSpeciale.getDescrizione(), offertaSpeciale.getFotoUrl());
				
				offertaSpecialeService.save(offertaSpeciale);
				
			} 
			
			catch(Exception e) {
				
				bindingResult.addError(new FieldError("offertaSpeciale", "titolo", offertaSpeciale.getTitolo(), false, null, null, "Nome must be unique"));
				model.addAttribute("offertaSpeciale", offertaSpeciale);
				model.addAttribute("title", "Edit");
				
				return "offertaSpeciale/form";
			}
			
			return "redirect:/pizza/"+ pizza_id;
		}
		
	}
	
	@PostMapping("/pizza/{pizza_id}/offertaSpeciale/delete/{id}")
	public String routeDelete( RedirectAttributes redirectAttribute, @PathVariable int pizza_id, @PathVariable int id) {
		
		OffertaSpeciale offertaSpeciale = offertaSpecialeService.findById(id);
		
		offertaSpecialeService.delete(offertaSpeciale);
		
		redirectAttribute.addFlashAttribute("deletedOffertaSpeciale", offertaSpeciale);
		
//		System.out.println(offertaSpeciale.getTitolo());
		
		return "redirect:/pizza/"+ pizza_id;
	}

}
