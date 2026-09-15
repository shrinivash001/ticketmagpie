package com.ticketmagpie.controllers;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

import java.io.IOException;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import com.ticketmagpie.Concert;
import com.ticketmagpie.User;
import com.ticketmagpie.infrastructure.persistence.ConcertRepository;
import com.ticketmagpie.infrastructure.persistence.UserRepository;

@Controller
@RequestMapping("/user/admin")
@PreAuthorize("hasRole('ADMIN')") // enforce at the controller level, don't rely on caller checks alone
public class AdminController {

  // Whitelist of roles that can actually be granted through this form.
  private static final List<String> ALLOWED_ROLES = Arrays.asList("USER", "ORGANIZER", "ADMIN");

  private static final List<String> ALLOWED_IMAGE_TYPES =
      Arrays.asList("image/png", "image/jpeg", "image/webp");

  private static final long MAX_IMAGE_BYTES = 5L * 1024 * 1024; // 5MB

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private ConcertRepository concertRepository;

  @Autowired
  private PasswordEncoder passwordEncoder; // e.g. BCryptPasswordEncoder bean

  @RequestMapping("")
  public String home() {
    return "admin/home";
  }

  @RequestMapping(value = "/users", method = GET)
  public String listUsers(Model model) {
    model.addAttribute("users", userRepository.getAllUsers());
    return "admin/users";
  }

  @RequestMapping(value = "/users", method = POST)
  public String createUser(@RequestParam("username") String username,
      @RequestParam(required = false, name = "email") String email,
      @RequestParam("role") String role,
      @RequestParam("password") String password,
      Model model) {

    username = username == null ? "" : username.trim();
    if (username.isEmpty() || username.length() > 64) {
      model.addAttribute("error", "Invalid username.");
      return listUsers(model);
    }

    if (!ALLOWED_ROLES.contains(role)) {
      model.addAttribute("error", "Invalid role.");
      return listUsers(model);
    }

    if (password == null || password.length() < 8) {
      model.addAttribute("error", "Password must be at least 8 characters.");
      return listUsers(model);
    }

    // Prevent silently overwriting an existing account via upsert-by-username.
    if (userRepository.findByUsername(username).isPresent()) {
      model.addAttribute("error", "Username already exists.");
      return listUsers(model);
    }

    String hashed = passwordEncoder.encode(password);
    userRepository.save(new User(username, hashed, email, role));

    return "redirect:/user/admin/users"; // POST-redirect-GET: avoid resubmission on refresh
  }

  @RequestMapping(value = "/users/delete", method = POST)
  public String deleteUser(@RequestParam("username") String username, Model model) {
    Optional<User> existing = userRepository.findByUsername(username);
    if (existing.isEmpty()) {
      model.addAttribute("error", "User not found.");
      return listUsers(model);
    }
    userRepository.delete(username);
    return "redirect:/user/admin/users";
  }

  @RequestMapping(value = "/concerts", method = GET)
  public String listConcerts(Model model) {
    model.addAttribute("concerts", concertRepository.getAllConcerts());
    return "admin/concerts";
  }

  @RequestMapping(value = "/concerts/delete", method = POST)
  public String deleteConcert(@RequestParam("id") int id, Model model) {
    boolean existed = concertRepository.delete(id);
    if (!existed) {
      model.addAttribute("error", "Concert not found.");
      return listConcerts(model);
    }
    return "redirect:/user/admin/concerts";
  }

  @RequestMapping(value = "/concerts", method = POST)
  public String createConcert(@RequestParam("band") String band,
      @RequestParam("date") String date,
      @RequestParam("description") String description,
      @RequestParam("image") MultipartFile imageAsMultipartFile,
      Model model) {

    band = band == null ? "" : band.trim();
    description = description == null ? "" : description.trim();

    if (band.isEmpty() || band.length() > 128) {
      model.addAttribute("error", "Invalid band name.");
      return listConcerts(model);
    }

    if (description.length() > 2000) {
      model.addAttribute("error", "Description too long.");
      return listConcerts(model);
    }

    try {
      LocalDate.parse(date); // expects ISO-8601 (yyyy-MM-dd); adjust formatter if you use a different format
    } catch (DateTimeParseException | NullPointerException e) {
      model.addAttribute("error", "Invalid date format.");
      return listConcerts(model);
    }

    if (imageAsMultipartFile == null || imageAsMultipartFile.isEmpty()) {
      model.addAttribute("error", "Image is required.");
      return listConcerts(model);
    }

    if (imageAsMultipartFile.getSize() > MAX_IMAGE_BYTES) {
      model.addAttribute("error", "Image too large (max 5MB).");
      return listConcerts(model);
    }

    String contentType = imageAsMultipartFile.getContentType();
    if (contentType == null || !ALLOWED_IMAGE_TYPES.contains(contentType)) {
      model.addAttribute("error", "Unsupported image type.");
      return listConcerts(model);
    }

    byte[] imageBytes;
    try {
      imageBytes = imageAsMultipartFile.getBytes();
    } catch (IOException e) {
      model.addAttribute("error", "Failed to read uploaded image.");
      return listConcerts(model);
    }

    concertRepository.save(new Concert(null, band, date, description, null, imageBytes));

    return "redirect:/user/admin/concerts";
  }
}
