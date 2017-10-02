package rmontag.jsfexample.common;

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.inject.Named;

@Named
@SessionScoped
public class Hello implements Serializable {

	private static final long serialVersionUID = 1L;

	private String name = "default";

	public Hello() {

	}

	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}

	@PostConstruct
	public void reset() {
		System.out.println("@PostConstruct Hello");
	}
}