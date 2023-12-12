package org.java.spring.serv;

import java.util.List;

import org.java.spring.pojo.OffertaSpeciale;
import org.java.spring.repo.OffertaSpecialeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OffertaSpecialeService {
	
	@Autowired
	private OffertaSpecialeRepository offertaSpecialeRepo;
	
	public List<OffertaSpeciale> findAll() {
		
		return offertaSpecialeRepo.findAll();
	}
	
	public OffertaSpeciale findById(int id) {
		
		return offertaSpecialeRepo.findById(id).get();
	}
	
	public void save(OffertaSpeciale offertaSpeciale) {
		
		offertaSpecialeRepo.save(offertaSpeciale);
	}
	
	public void delete(OffertaSpeciale offertaSpeciale) {
		
		offertaSpecialeRepo.delete(offertaSpeciale);
		
	}
	
	public void deleteById(int id) {
		
		offertaSpecialeRepo.deleteById(id);
		
	}
}
